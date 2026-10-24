#!/usr/bin/env python3
"""Build and validate a first-install GuToChat configuration without writes.

The bootstrap boundary is deliberately narrow: deployment identity comes from
an explicit private seed file, while hardware-owned values come from one
explicit candidate-owned profile and binding.  The helper never discovers
hardware, changes radio parameters, installs dependencies, touches services or
writes configuration files.
"""
from __future__ import annotations

import argparse
import copy
import json
import shlex
from pathlib import Path
from typing import Any, Mapping

from hardware_profile_runtime import resolve_runtime_config


PRODUCT_VERSION = "2.5.0-beta5"
PROFILE_OWNED_KEYS = frozenset(
    {
        "hardware_profile",
        "hardware_profile_path",
        "hardware_binding",
        "serial_port",
        "api_host",
        "api_port",
    }
)
IDENTITY_KEYS = (
    "node_name",
    "station_name",
    "station_id",
    "station_callsign",
    "address",
    "database",
    "contacts_file",
    "ui_state_file",
    "ui_language",
    "offline_map_directory",
    "offline_map_path",
)
PATH_KEYS = (
    "database",
    "contacts_file",
    "ui_state_file",
    "offline_map_directory",
    "offline_map_path",
)


class BootstrapConfigError(ValueError):
    """Stable bootstrap validation error."""


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise BootstrapConfigError(f"{label}_READ_FAILED: {type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise BootstrapConfigError(f"{label}_ROOT_INVALID")
    return value


def _expand_home(value: Any, home: Path) -> Any:
    if not isinstance(value, str) or not value:
        return value
    if value == "~" or value == "$HOME":
        return str(home)
    if value.startswith("~/"):
        return str(home / value[2:])
    if value.startswith("$HOME/"):
        return str(home / value[len("$HOME/"):])
    return value


def _required_text(config: Mapping[str, Any], key: str) -> str:
    value = " ".join(str(config.get(key) or "").split())
    if not value or value.upper() in {"CHANGE-ME", "CHANGEME"}:
        raise BootstrapConfigError(f"BOOTSTRAP_REQUIRED_FIELD: {key}")
    return value


def _validate_address(value: Any) -> int:
    try:
        address = int(value)
    except (TypeError, ValueError) as exc:
        raise BootstrapConfigError("BOOTSTRAP_ADDRESS_INVALID") from exc
    if not 0 <= address <= 65535:
        raise BootstrapConfigError("BOOTSTRAP_ADDRESS_INVALID")
    return address


def _binding(path: Path, role: str) -> dict[str, Any]:
    binding = _load_object(path, "BOOTSTRAP_BINDING")
    selected_role = str(binding.get("role") or "").strip().lower()
    if selected_role == "mobile":
        selected_role = "field"
    if selected_role != role:
        raise BootstrapConfigError(
            f"BOOTSTRAP_BINDING_ROLE_MISMATCH: selected={selected_role or 'missing'} requested={role}"
        )
    if bool(binding.get("legacy_fallback_allowed")):
        raise BootstrapConfigError("BOOTSTRAP_LEGACY_FALLBACK_FORBIDDEN")
    return binding


def build_bootstrap_config(
    seed: Mapping[str, Any],
    *,
    role: str,
    validation_profile_path: Path,
    installed_profile_path: Path,
    binding: Mapping[str, Any],
    home: Path,
    identity_defaults: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return final config and a privacy-reduced validation report.

    ``validation_profile_path`` points to the immutable candidate copy used
    during dry-run.  ``installed_profile_path`` is the path that will exist
    after activation and is the only profile path written to the final config.
    """
    role = str(role).strip().lower()
    if role == "mobile":
        role = "field"
    if role not in {"base", "field"}:
        raise BootstrapConfigError("BOOTSTRAP_ROLE_INVALID")
    if not isinstance(seed, Mapping):
        raise BootstrapConfigError("BOOTSTRAP_SEED_ROOT_INVALID")

    config: dict[str, Any] = {}
    if identity_defaults:
        for key in IDENTITY_KEYS:
            if key in identity_defaults:
                config[key] = copy.deepcopy(identity_defaults[key])
    config.update(copy.deepcopy(dict(seed)))

    forbidden = sorted(PROFILE_OWNED_KEYS.intersection(config))
    if forbidden:
        raise BootstrapConfigError(
            "BOOTSTRAP_PROFILE_OWNED_FIELD_PRESENT: " + ",".join(forbidden)
        )

    existing_role = str(config.get("role") or "").strip().lower()
    if existing_role == "mobile":
        existing_role = "field"
    if existing_role and existing_role != role:
        raise BootstrapConfigError(
            f"BOOTSTRAP_SEED_ROLE_MISMATCH: selected={existing_role} requested={role}"
        )
    existing_version = str(config.get("app_version") or "").strip()
    if existing_version and existing_version != PRODUCT_VERSION:
        raise BootstrapConfigError(
            f"BOOTSTRAP_SEED_VERSION_MISMATCH: {existing_version}"
        )

    config["app_version"] = PRODUCT_VERSION
    config["role"] = role
    config["node_name"] = _required_text(config, "node_name")
    config["station_name"] = _required_text(config, "station_name")
    config["station_id"] = _required_text(config, "station_id")
    config["address"] = _validate_address(config.get("address"))

    home = home.resolve()
    defaults = {
        "database": str(home / ".local" / "share" / "lorachat" / "messages.db"),
        "contacts_file": str(home / ".config" / "lorachat-v2" / "contacts.json"),
        "ui_state_file": str(home / ".config" / "lorachat-v2" / "ui-state.json"),
        "offline_map_directory": str(home / ".local" / "share" / "gutochat" / "maps"),
        "offline_map_path": "",
        "ui_language": "nb",
    }
    for key, value in defaults.items():
        config.setdefault(key, value)
    for key in PATH_KEYS:
        if key in config:
            config[key] = _expand_home(config[key], home)

    # Validate the candidate-owned source profile before any installation.  The
    # final config differs only by the profile path that will point at the
    # byte-identical copy inside program_root after activation.
    validation_config = copy.deepcopy(config)
    validation_config["hardware_profile_path"] = str(validation_profile_path.resolve())
    validation_config["hardware_binding"] = copy.deepcopy(dict(binding))
    resolved = resolve_runtime_config(validation_config, home / ".config/lorachat-v2/config.json")

    runtime = resolved.get("_hardware_profile_runtime")
    if not isinstance(runtime, dict):
        raise BootstrapConfigError("BOOTSTRAP_PROFILE_RUNTIME_MISSING")
    if str(resolved.get("role")) != role:
        raise BootstrapConfigError("BOOTSTRAP_RESOLVED_ROLE_MISMATCH")

    config["hardware_profile_path"] = str(installed_profile_path)
    config["hardware_binding"] = copy.deepcopy(dict(binding))

    report = {
        "role": role,
        "profile_id": str(runtime.get("profile_id", "")),
        "profile_version": str(runtime.get("profile_version", "")),
        "support_class": str(runtime.get("support_class", "")),
        "binding_id": str(runtime.get("binding_id", "")),
        "serial_port": str(resolved.get("serial_port", "")),
        "api_host": str(resolved.get("api_host", "127.0.0.1")),
        "api_port": int(resolved.get("api_port", 8765)),
        "enabled_capabilities": sorted(str(item) for item in runtime.get("enabled_capabilities", [])),
        "platform_family": str(runtime.get("platform_family", "")),
        "service_manager_adapter_id": str(runtime.get("service_manager_adapter_id", "")),
        "local_radio_adapter_id": str(runtime.get("local_radio_adapter_id", "")),
        "gpio_adapter_id": str(runtime.get("gpio_adapter_id", "")),
        "serial_selector_strategy": str(runtime.get("serial_selector_strategy", "")),
        "hardware_probe_performed": bool(runtime.get("hardware_probe_performed", False)),
        "write_performed": False,
    }
    return config, report


def _profile_contract(profile: Mapping[str, Any], home: Path) -> dict[str, Any]:
    paths = profile.get("paths") or {
        "program_root": "$HOME/lorachat-v2",
        "config_root": "$HOME/.config/lorachat-v2",
        "installer_backup_root": "$HOME/lorachat-v2-backups",
    }
    runtime = profile.get("python_runtime") or {
        "main_interpreter": "/usr/bin/python3",
        "meshtastic_interpreter": "$HOME/meshtastic-venv/bin/python",
    }
    return {
        "program_root": _expand_home(str(paths["program_root"]), home),
        "config_root": _expand_home(str(paths["config_root"]), home),
        "installer_backup_root": _expand_home(str(paths["installer_backup_root"]), home),
        "main_interpreter": _expand_home(str(runtime["main_interpreter"]), home),
        "meshtastic_interpreter": _expand_home(str(runtime["meshtastic_interpreter"]), home),
        "required_groups": [str(item) for item in profile.get("required_groups", [])],
    }


def _shell(report: Mapping[str, Any], contract: Mapping[str, Any], config: Mapping[str, Any]) -> None:
    values = {
        "BOOTSTRAP_CONFIG_JSON": json.dumps(dict(config), ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        "BOOTSTRAP_ROLE": report["role"],
        "BOOTSTRAP_PROFILE_ID": report["profile_id"],
        "BOOTSTRAP_PROFILE_VERSION": report["profile_version"],
        "BOOTSTRAP_SUPPORT_CLASS": report["support_class"],
        "BOOTSTRAP_BINDING_ID": report["binding_id"],
        "BOOTSTRAP_SERIAL_PORT": report["serial_port"],
        "BOOTSTRAP_API_HOST": report["api_host"],
        "BOOTSTRAP_API_PORT": report["api_port"],
        "BOOTSTRAP_CAPABILITIES": ",".join(report["enabled_capabilities"]),
        "BOOTSTRAP_PLATFORM_FAMILY": report["platform_family"],
        "BOOTSTRAP_SERVICE_MANAGER": report["service_manager_adapter_id"],
        "BOOTSTRAP_RADIO_ADAPTER": report["local_radio_adapter_id"],
        "BOOTSTRAP_GPIO_ADAPTER": report["gpio_adapter_id"],
        "BOOTSTRAP_PROGRAM_ROOT": contract["program_root"],
        "BOOTSTRAP_CONFIG_ROOT": contract["config_root"],
        "BOOTSTRAP_BACKUP_ROOT": contract["installer_backup_root"],
        "BOOTSTRAP_MAIN_PYTHON": contract["main_interpreter"],
        "BOOTSTRAP_MESH_PYTHON": contract["meshtastic_interpreter"],
        "BOOTSTRAP_REQUIRED_GROUPS": ",".join(contract["required_groups"]),
    }
    for key, value in values.items():
        print(f"{key}={shlex.quote(str(value))}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", required=True)
    parser.add_argument("--role", required=True, choices=("base", "field", "mobile"))
    parser.add_argument("--profile", required=True)
    parser.add_argument("--installed-profile", required=True)
    parser.add_argument("--binding", required=True)
    parser.add_argument("--home", required=True)
    parser.add_argument("--identity-from")
    parser.add_argument("--format", choices=("config", "report", "shell"), default="config")
    args = parser.parse_args()

    role = "field" if args.role == "mobile" else args.role
    seed = _load_object(Path(args.seed), "BOOTSTRAP_SEED")
    binding = _binding(Path(args.binding), role)
    identity_defaults = None
    if args.identity_from:
        identity_defaults = _load_object(Path(args.identity_from), "BOOTSTRAP_IDENTITY")
    config, report = build_bootstrap_config(
        seed,
        role=role,
        validation_profile_path=Path(args.profile),
        installed_profile_path=Path(args.installed_profile),
        binding=binding,
        home=Path(args.home),
        identity_defaults=identity_defaults,
    )
    profile = _load_object(Path(args.profile), "BOOTSTRAP_PROFILE")
    contract = _profile_contract(profile, Path(args.home).resolve())

    if args.format == "config":
        print(json.dumps(config, indent=2, ensure_ascii=False, sort_keys=True))
    elif args.format == "report":
        combined = dict(report)
        combined["installer_contract"] = contract
        print(json.dumps(combined, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        _shell(report, contract, config)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BootstrapConfigError as exc:
        print(str(exc), file=__import__("sys").stderr)
        raise SystemExit(1)
