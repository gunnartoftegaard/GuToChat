"""Fail-closed runtime configuration boundary for GuToChat hardware profiles.

PRE-A3-A2.7 beta5 candidate; beta4 reference remains immutable. The no-profile legacy path remains semantic:
when no ``hardware_profile_path`` is configured this module returns an
independent copy of the original configuration without probing hardware,
reading extra files, or changing defaults.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Mapping

from hardware_profile import (
    ProfileFailure,
    approved_reference_registry,
    diagnostics_profile_view,
    load_profile,
    normalize_role,
    validate_binding,
    validate_privacy_reduced_report,
    validate_profile,
)


class RuntimeProfileError(ValueError):
    """Stable public wrapper around profile validation failures."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(reason_code if not detail else f"{reason_code}: {detail}")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_json_object(path: Path, reason: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeProfileError(reason, f"{type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeProfileError(reason, "top-level JSON value must be an object")
    return value




def _read_product_version() -> str:
    version_path = _repo_root() / "VERSION"
    try:
        version = version_path.read_text(encoding="utf-8").strip()
    except Exception as exc:
        raise RuntimeProfileError("PRODUCT_VERSION_READ_FAILED", f"{type(exc).__name__}: {exc}") from exc
    if not version:
        raise RuntimeProfileError("PRODUCT_VERSION_READ_FAILED", "VERSION is empty")
    return version


def _load_reference_registry() -> dict[tuple[str, str], dict[str, Any]]:
    paths = [
        _repo_root() / "hardware_profiles/examples/rpi-waveshare-sx126x-reference-v1.json",
        _repo_root() / "hardware_profiles/references/rpi-waveshare-sx126x-reference-v1.1.0-beta4.json",
        _repo_root() / "hardware_profiles/references/rpi-waveshare-sx126x-reference-v1.2.0-beta5.json",
    ]
    references = [_load_json_object(path, "REFERENCE_PROFILE_READ_FAILED") for path in paths]
    try:
        return approved_reference_registry(references)
    except ProfileFailure as exc:
        raise RuntimeProfileError(exc.reason_code, exc.detail) from exc

def _binding_from_config(config: Mapping[str, Any], profile: Mapping[str, Any]) -> dict[str, Any]:
    binding = config.get("hardware_binding")
    if binding is None:
        raise RuntimeProfileError("PROFILE_BINDING_REQUIRED")
    if not isinstance(binding, Mapping):
        raise RuntimeProfileError("PROFILE_BINDING_INVALID", "hardware_binding must be an object")
    result = dict(binding)
    # Role remains a program/deployment decision. It may be written once in the
    # binding, but it must agree with any existing config role after legacy alias
    # normalization. No role is inferred from the profile.
    configured_role = config.get("role")
    if configured_role not in (None, ""):
        try:
            expected = normalize_role(configured_role)
            actual = normalize_role(result.get("role"))
        except ProfileFailure as exc:
            raise RuntimeProfileError(exc.reason_code, exc.detail) from exc
        if expected != actual:
            raise RuntimeProfileError("CONFIG_PROFILE_ROLE_CONFLICT")
    if result.get("hardware_profile_id") != profile.get("profile_id"):
        raise RuntimeProfileError("PROFILE_BINDING_ID_MISMATCH")
    if result.get("hardware_profile_version") != profile.get("profile_version"):
        raise RuntimeProfileError("PROFILE_BINDING_VERSION_MISMATCH")
    return result


def _set_or_require_equal(config: dict[str, Any], key: str, value: Any) -> None:
    if key in config and config[key] not in (None, "") and config[key] != value:
        raise RuntimeProfileError("CONFIG_PROFILE_CONFLICT", key)
    config[key] = value


def resolve_runtime_config(config: Mapping[str, Any], config_path: Path) -> dict[str, Any]:
    """Return a validated runtime configuration without writes or discovery.

    The profile feature is opt-in through an explicit absolute
    ``hardware_profile_path``. Embedded profile objects, relative paths,
    automatic discovery, and fallback are rejected.
    """
    if not isinstance(config, Mapping):
        raise RuntimeProfileError("CONFIG_ROOT_INVALID")
    resolved = copy.deepcopy(dict(config))

    if "hardware_profile" in resolved:
        raise RuntimeProfileError("EMBEDDED_PROFILE_FORBIDDEN")
    selected = resolved.get("hardware_profile_path")
    if selected in (None, ""):
        return resolved
    if not isinstance(selected, str):
        raise RuntimeProfileError("PROFILE_PATH_INVALID")

    profile_path = Path(selected)
    if not profile_path.is_absolute():
        raise RuntimeProfileError("PROFILE_PATH_INVALID", "absolute local path required")

    schema_path = _repo_root() / "hardware_profiles/spec/gutochat-hardware-profile-v1.schema.json"
    schema = _load_json_object(schema_path, "PROFILE_SCHEMA_READ_FAILED")
    product_version = _read_product_version()
    registry = _load_reference_registry()

    try:
        loaded = load_profile(profile_path)
        validated = validate_profile(
            loaded.raw,
            schema,
            program_version=product_version,
            approved_support_registry=registry,
        )
        binding = validate_binding(_binding_from_config(resolved, validated.profile), validated.profile)
    except ProfileFailure as exc:
        raise RuntimeProfileError(exc.reason_code, exc.detail) from exc

    if bool(binding.get("legacy_fallback_allowed")):
        raise RuntimeProfileError("LEGACY_FALLBACK_FORBIDDEN")

    profile = validated.profile
    serial = profile["serial_selector"]
    serial_strategy = str(serial.get("strategy") or "")
    # These three strategies all name one exact local device path.  The
    # by-id/by-path variants are stable Linux symlinks and therefore improve
    # portability without adding discovery, wildcard matching or fallback.
    if serial_strategy not in {"explicit_path", "linux_by_id", "linux_by_path"}:
        raise RuntimeProfileError("SERIAL_RUNTIME_SELECTOR_UNSUPPORTED")
    if serial.get("allow_fallback"):
        raise RuntimeProfileError("SERIAL_RUNTIME_SELECTOR_UNSUPPORTED")

    _set_or_require_equal(resolved, "role", binding["role"])
    _set_or_require_equal(resolved, "serial_port", serial["value"])
    service_contract = profile.get("service_contract")
    if isinstance(service_contract, Mapping):
        _set_or_require_equal(resolved, "api_host", service_contract["api_bind"])
        _set_or_require_equal(resolved, "api_port", service_contract["private_lora_port"])

    view = diagnostics_profile_view(profile, ("PASS",))
    validate_privacy_reduced_report(view)
    resolved["_hardware_profile_runtime"] = {
        **view,
        "canonical_sha256": validated.canonical_sha256,
        "binding_id": binding["binding_id"],
        "role": binding["role"],
        "enabled_capabilities": binding["enabled_capabilities"],
        "declared_capabilities": sorted(str(item) for item in profile.get("capabilities", [])),
        "platform_family": str(profile.get("platform_family", "")),
        "serial_selector_strategy": serial_strategy,
        "local_radio_adapter_id": str(
            profile.get("local_radio_driver", {}).get("adapter_id", "")
        ),
        "gpio_adapter_id": str(
            profile.get("gpio_backend", {}).get("adapter_id", "")
        ),
        "service_manager_adapter_id": str(
            profile.get("service_manager", {}).get("adapter_id", "")
        ),
        "source_sha256": loaded.source_sha256,
        "write_performed": False,
        "hardware_probe_performed": False,
    }
    return resolved


def load_runtime_config(config_path: Path) -> dict[str, Any]:
    """Read a config JSON object and apply the optional profile boundary."""
    config = _load_json_object(config_path, "CONFIG_READ_FAILED")
    return resolve_runtime_config(config, config_path)
