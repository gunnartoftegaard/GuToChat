#!/usr/bin/env python3
"""Resolve the local installer platform contract without probing hardware.

The current GuToChat installer remains a Linux/systemd installer.  This helper
separates that intentional platform boundary from values that are already
carried by an activated hardware profile, notably Python interpreter paths.
It performs no writes, hardware discovery, service operations or network I/O.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
from typing import Any

from hardware_profile import LEGACY_PATHS, REFERENCE_SEMANTICS
from hardware_profile_runtime import load_runtime_config


def _expand_home(value: str, home: Path) -> str:
    if value == "$HOME":
        return str(home)
    if value.startswith("$HOME/"):
        return str(home / value[len("$HOME/"):])
    return value


def resolve_installer_contract(config_path: Path, *, home: Path | None = None) -> dict[str, Any]:
    """Return the write-free installer/runtime contract for one config."""
    home = (home or Path.home()).resolve()
    resolved = load_runtime_config(config_path)
    runtime = resolved.get("_hardware_profile_runtime")

    if isinstance(runtime, dict):
        # The profile has already passed the fail-closed runtime validator.
        profile_path = Path(str(resolved["hardware_profile_path"]))
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        paths = profile.get("paths") or LEGACY_PATHS
        python_runtime = profile.get("python_runtime") or {
            "main_interpreter": REFERENCE_SEMANTICS["main_interpreter"],
            "meshtastic_interpreter": REFERENCE_SEMANTICS["meshtastic_interpreter"],
        }
        mode = "profile"
        platform_family = str(profile.get("platform_family") or "")
        service_manager = str((profile.get("service_manager") or {}).get("adapter_id") or "")
        profile_id = str(profile.get("profile_id") or "")
        profile_version = str(profile.get("profile_version") or "")
    else:
        paths = LEGACY_PATHS
        python_runtime = {
            "main_interpreter": REFERENCE_SEMANTICS["main_interpreter"],
            "meshtastic_interpreter": REFERENCE_SEMANTICS["meshtastic_interpreter"],
        }
        mode = "legacy"
        # Legacy 2.x installations have always been Linux/systemd deployments.
        platform_family = "linux-legacy-systemd"
        service_manager = "systemd-v1"
        profile_id = ""
        profile_version = ""

    contract = {
        "mode": mode,
        "platform_family": platform_family,
        "service_manager_adapter_id": service_manager,
        "program_root": _expand_home(str(paths["program_root"]), home),
        "config_root": _expand_home(str(paths["config_root"]), home),
        "installer_backup_root": _expand_home(str(paths["installer_backup_root"]), home),
        "main_interpreter": _expand_home(str(python_runtime["main_interpreter"]), home),
        "meshtastic_interpreter": _expand_home(str(python_runtime["meshtastic_interpreter"]), home),
        "profile_id": profile_id,
        "profile_version": profile_version,
    }
    return contract


def _emit_shell(contract: dict[str, Any]) -> None:
    mapping = {
        "INSTALL_CONTRACT_MODE": contract["mode"],
        "INSTALL_PLATFORM_FAMILY": contract["platform_family"],
        "INSTALL_SERVICE_MANAGER": contract["service_manager_adapter_id"],
        "INSTALL_PROGRAM_ROOT": contract["program_root"],
        "INSTALL_CONFIG_ROOT": contract["config_root"],
        "INSTALL_BACKUP_ROOT": contract["installer_backup_root"],
        "INSTALL_MAIN_INTERPRETER": contract["main_interpreter"],
        "INSTALL_MESHTASTIC_INTERPRETER": contract["meshtastic_interpreter"],
        "INSTALL_PROFILE_ID": contract["profile_id"],
        "INSTALL_PROFILE_VERSION": contract["profile_version"],
    }
    for key, value in mapping.items():
        print(f"{key}={shlex.quote(str(value))}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--home", default=os.environ.get("HOME", ""))
    parser.add_argument("--format", choices=("json", "shell"), default="json")
    args = parser.parse_args()

    home = Path(args.home).resolve() if args.home else Path.home().resolve()
    contract = resolve_installer_contract(Path(args.config), home=home)
    if args.format == "shell":
        _emit_shell(contract)
    else:
        print(json.dumps(contract, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
