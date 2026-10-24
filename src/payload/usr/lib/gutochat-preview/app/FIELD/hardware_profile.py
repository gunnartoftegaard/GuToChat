"""GuToChat hardware-profile validation and adapter contract.

This module implements the owner-approved PORT-K1 design contract for
``gutochat-hardware-profile-v1``. PORT-K4 replaces the prototype-only external
JSON Schema dependency with a bundled deterministic validator. The module
performs no hardware probing, network access, backup, service mutation, radio
configuration, database mutation, map access, or role inference.
"""
from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable, Mapping, Sequence



PROFILE_SCHEMA_NAME = "gutochat-hardware-profile-v1"
REFERENCE_PROFILE_ID = "rpi-waveshare-sx126x-reference-v1"
HISTORICAL_REFERENCE_PROFILE_VERSION = "1.0.0"
BETA4_REFERENCE_PROFILE_VERSION = "1.1.0"

CANONICAL_ROLES = frozenset({"base", "field"})
ROLE_ALIASES = {"mobile": "field"}

PROFILE_CAPABILITIES = frozenset(
    {
        "private_lora",
        "meshtastic_local_868",
        "meshtastic_local_433",
        "meshtastic_gateway_descriptors",
        "gnss",
        "gui",
        "diagnostics",
    }
)
ROLE_CAPABILITY_POLICY = {
    "field": frozenset(
        {
            "private_lora",
            "meshtastic_gateway_descriptors",
            "gnss",
            "gui",
            "diagnostics",
        }
    ),
    "base": frozenset(
        {
            "private_lora",
            "meshtastic_local_868",
            "meshtastic_local_433",
            "meshtastic_gateway_descriptors",
            "gnss",
            "gui",
            "diagnostics",
        }
    ),
}

LEGACY_SERVICE_CONTRACT = {
    "api_bind": "127.0.0.1",
    "private_lora_service": "lorad-v2.service",
    "private_lora_port": 8765,
    "meshtastic_868_service": "meshbridge-v2.service",
    "meshtastic_868_port": 8766,
    "meshtastic_433_service": "meshbridge433-v2.service",
    "meshtastic_433_port": 8767,
}
LEGACY_PATHS = {
    "program_root": "$HOME/lorachat-v2",
    "config_root": "$HOME/.config/lorachat-v2",
    "installer_backup_root": "$HOME/lorachat-v2-backups",
}
REFERENCE_SEMANTICS = {
    "serial_port": "/dev/ttyS0",
    "uart_baudrate": 9600,
    "gpio_numbering": "BCM",
    "gpio_m0": 22,
    "gpio_m1": 27,
    "main_interpreter": "/usr/bin/python3",
    "meshtastic_interpreter": "$HOME/meshtastic-venv/bin/python",
    "required_groups": ["dialout", "gpio"],
    **LEGACY_SERVICE_CONTRACT,
    **LEGACY_PATHS,
}

SECRET_FIELD_NAMES = frozenset(
    {
        "psk",
        "private_key",
        "channel_url",
        "secret",
        "secrets",
        "api_token",
        "password",
    }
)
RADIO_MUTATION_FIELD_NAMES = frozenset(
    {
        "frequency",
        "freq",
        "power",
        "firmware",
        "position_precision",
        "radio_parameters",
        "radio_config",
    }
)
AUTODETECT_OR_NETWORK_FIELD_NAMES = frozenset(
    {
        "autodetect",
        "network_access",
        "remote_lookup",
        "remote_url",
        "discovery_url",
    }
)
ROLE_MUTATION_FIELD_NAMES = frozenset(
    {
        "role",
        "requested_role",
        "role_change",
        "inferred_role",
        "auto_role",
    }
)
PRIVACY_FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "hostname",
        "host_name",
        "mac",
        "mac_address",
        "serial_number",
        "station_identity",
        "station_id",
        "callsign",
        "message",
        "messages",
        "contact",
        "contacts",
        "position",
        "positions",
        "coordinates",
        "latitude",
        "longitude",
    }
)

PROFILE_ID_RE = re.compile(r"^[a-z0-9]+(?:[a-z0-9._-]*[a-z0-9])?$")
PROFILE_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$")
SAFE_EXPLICIT_SERIAL_RE = re.compile(r"^/dev/(?!.*[?*])[A-Za-z0-9._/-]+$")
SAFE_BY_ID_RE = re.compile(r"^/dev/serial/by-id/(?!.*[?*])[A-Za-z0-9._:+-]+$")
SAFE_BY_PATH_RE = re.compile(r"^/dev/serial/by-path/(?!.*[?*])[A-Za-z0-9._:+-]+$")
SAFE_SYNTHETIC_RE = re.compile(r"^synthetic:[A-Za-z0-9._-]+$")


@dataclass(frozen=True)
class ProfileFailure(Exception):
    """Stable fail-closed error used by all prototype adapters."""

    reason_code: str
    detail: str = ""

    def __str__(self) -> str:
        return self.reason_code if not self.detail else f"{self.reason_code}: {self.detail}"


@dataclass(frozen=True)
class LoadedProfile:
    raw: dict[str, Any]
    source_sha256: str
    source_path: str


@dataclass(frozen=True)
class ValidatedProfile:
    profile: dict[str, Any]
    canonical_json: bytes
    canonical_sha256: str
    reason_codes: tuple[str, ...] = ("PASS",)


@dataclass(frozen=True)
class ValidationOutcome:
    ok: bool
    reason_codes: tuple[str, ...]
    detail: str = ""
    normalized_profile: dict[str, Any] | None = None
    canonical_sha256: str | None = None


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON with a trailing LF."""
    text = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return (text + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_profile(explicit_local_path: str | os.PathLike[str]) -> LoadedProfile:
    """Load one explicitly selected local JSON profile without discovery or writes."""
    try:
        path = Path(explicit_local_path)
    except Exception as exc:
        raise ProfileFailure("PROFILE_PATH_INVALID", str(exc)) from exc

    if not path.is_absolute():
        raise ProfileFailure("PROFILE_PATH_INVALID", "profile path must be absolute")
    if not path.is_file():
        raise ProfileFailure("PROFILE_TARGET_MISSING", str(path))

    try:
        data = path.read_bytes()
    except Exception as exc:
        raise ProfileFailure("PROFILE_READ_FAILED", f"{type(exc).__name__}: {exc}") from exc

    try:
        parsed = json.loads(data.decode("utf-8-sig"))
    except Exception as exc:
        raise ProfileFailure("PROFILE_PARSE_FAILED", f"{type(exc).__name__}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ProfileFailure("PROFILE_ROOT_INVALID", "top-level value must be an object")

    return LoadedProfile(raw=parsed, source_sha256=sha256_bytes(data), source_path=str(path))


def _walk_object(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str, Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            yield path, key_text, child
            yield from _walk_object(child, path + (key_text,))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            yield from _walk_object(child, path + (str(index),))


def _reject_forbidden_profile_fields(profile: Mapping[str, Any]) -> None:
    for parent, key, value in _walk_object(profile):
        lowered = key.strip().lower()
        if lowered in SECRET_FIELD_NAMES:
            raise ProfileFailure("SECRET_FIELD_FORBIDDEN", ".".join(parent + (key,)))
        if lowered in RADIO_MUTATION_FIELD_NAMES:
            raise ProfileFailure("RADIO_PARAMETER_CHANGE_FORBIDDEN", ".".join(parent + (key,)))
        if lowered in ROLE_MUTATION_FIELD_NAMES:
            raise ProfileFailure("ROLE_CHANGE_FORBIDDEN", ".".join(parent + (key,)))
        if lowered in AUTODETECT_OR_NETWORK_FIELD_NAMES:
            if bool(value):
                raise ProfileFailure("AUTODETECT_OR_NETWORK_FORBIDDEN", ".".join(parent + (key,)))


def _jsonschema_error_to_reason(error: Any) -> str:
    path = tuple(str(item) for item in getattr(error, "absolute_path", ()))
    validator = getattr(error, "validator", "")
    message = str(getattr(error, "message", ""))

    if validator == "additionalProperties" and path and path[0] == "paths":
        return "DATA_PATH_MUTATION_OUT_OF_SCOPE"
    if validator == "additionalProperties" and path and path[0] == "service_contract":
        return "SERVICE_CONTRACT_INCOMPATIBLE"
    if validator == "additionalProperties" and path and path[0] in {"gpio_backend", "gpio_numbering"}:
        return "GPIO_BACKEND_UNSUPPORTED"
    if validator == "additionalProperties":
        return "PROFILE_UNKNOWN_FIELD"
    if validator == "required":
        return "PROFILE_REQUIRED_FIELD_MISSING"
    if path and path[0] in {"profile_id", "profile_version"}:
        return "PROFILE_ID_OR_VERSION_INVALID"
    if path and path[0] == "serial_selector":
        if "allow_fallback" in path or "required_unique" in path or "?" in message or "*" in message:
            return "SERIAL_WILDCARD_OR_FALLBACK_FORBIDDEN"
        return "SERIAL_PATH_UNSAFE"
    if path and path[0] in {"gpio_backend", "gpio_numbering"}:
        return "GPIO_BACKEND_UNSUPPORTED"
    if path and path[0] == "uart_baudrate":
        return "UART_BAUDRATE_UNSUPPORTED"
    if path and path[0] == "capabilities":
        return "CAPABILITY_INVALID"
    if path and path[0] == "service_contract":
        if "api_bind" in path:
            return "NETWORK_EXPOSURE_FORBIDDEN"
        return "SERVICE_CONTRACT_INCOMPATIBLE"
    if path and path[0] == "paths":
        return "DATA_PATH_MUTATION_OUT_OF_SCOPE"
    if path and path[0] == "security":
        if "allow_autodetect" in path or "local_only" in path:
            return "AUTODETECT_OR_NETWORK_FORBIDDEN"
        if "allow_role_change" in path:
            return "ROLE_CHANGE_FORBIDDEN"
        if "allow_secret_fields" in path:
            return "SECRET_FIELD_FORBIDDEN"
        if "allow_radio_parameter_changes" in path:
            return "RADIO_PARAMETER_CHANGE_FORBIDDEN"
    return "PROFILE_SCHEMA_INVALID"



@dataclass(frozen=True)
class _SchemaIssue:
    validator: str
    absolute_path: tuple[str, ...]
    message: str


def _schema_type_ok(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    return False


def _schema_ref(root: Mapping[str, Any], reference: str) -> Mapping[str, Any]:
    if not reference.startswith("#/"):
        raise ProfileFailure("PROFILE_SCHEMA_INVALID", "only local schema references are supported")
    current: Any = root
    for component in reference[2:].split("/"):
        component = component.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or component not in current:
            raise ProfileFailure("PROFILE_SCHEMA_INVALID", f"unresolved schema reference: {reference}")
        current = current[component]
    if not isinstance(current, Mapping):
        raise ProfileFailure("PROFILE_SCHEMA_INVALID", f"schema reference is not an object: {reference}")
    return current


def _schema_issues(value: Any, node: Mapping[str, Any], root: Mapping[str, Any], path: tuple[str, ...] = ()) -> list[_SchemaIssue]:
    if "$ref" in node:
        return _schema_issues(value, _schema_ref(root, str(node["$ref"])), root, path)
    issues: list[_SchemaIssue] = []
    expected = node.get("type")
    if isinstance(expected, str) and not _schema_type_ok(value, expected):
        return [_SchemaIssue("type", path, f"expected {expected}")]
    if "const" in node and value != node["const"]:
        issues.append(_SchemaIssue("const", path, f"must equal {node['const']!r}"))
    if "enum" in node and value not in node["enum"]:
        issues.append(_SchemaIssue("enum", path, f"value is not in the permitted set"))
    if isinstance(value, str):
        if isinstance(node.get("minLength"), int) and len(value) < node["minLength"]:
            issues.append(_SchemaIssue("minLength", path, "string is too short"))
        if isinstance(node.get("maxLength"), int) and len(value) > node["maxLength"]:
            issues.append(_SchemaIssue("maxLength", path, "string is too long"))
        pattern = node.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            issues.append(_SchemaIssue("pattern", path, "string does not match required pattern"))
    if isinstance(value, int) and not isinstance(value, bool):
        if isinstance(node.get("minimum"), int) and value < node["minimum"]:
            issues.append(_SchemaIssue("minimum", path, "value is below minimum"))
        if isinstance(node.get("maximum"), int) and value > node["maximum"]:
            issues.append(_SchemaIssue("maximum", path, "value is above maximum"))
    if isinstance(value, list):
        if isinstance(node.get("minItems"), int) and len(value) < node["minItems"]:
            issues.append(_SchemaIssue("minItems", path, "array has too few items"))
        if node.get("uniqueItems") is True:
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for item in value]
            if len(encoded) != len(set(encoded)):
                issues.append(_SchemaIssue("uniqueItems", path, "array items are not unique"))
        item_schema = node.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                issues.extend(_schema_issues(item, item_schema, root, path + (str(index),)))
    if isinstance(value, Mapping):
        required = node.get("required")
        if isinstance(required, list):
            for name in required:
                if name not in value:
                    issues.append(_SchemaIssue("required", path, f"required property {name!r} is missing"))
        properties = node.get("properties")
        known = set(properties) if isinstance(properties, Mapping) else set()
        if node.get("additionalProperties") is False:
            for name in value:
                if name not in known:
                    issues.append(_SchemaIssue("additionalProperties", path, f"unexpected property {name!r}"))
        if isinstance(properties, Mapping):
            for name, child_schema in properties.items():
                if name in value and isinstance(child_schema, Mapping):
                    issues.extend(_schema_issues(value[name], child_schema, root, path + (str(name),)))
    all_of = node.get("allOf")
    if isinstance(all_of, list):
        for clause in all_of:
            if not isinstance(clause, Mapping):
                continue
            condition = clause.get("if")
            then = clause.get("then")
            if isinstance(condition, Mapping) and isinstance(then, Mapping):
                if not _schema_issues(value, condition, root, path):
                    issues.extend(_schema_issues(value, then, root, path))
            else:
                issues.extend(_schema_issues(value, clause, root, path))
    return issues


def _validate_schema(profile: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    """Validate the fixed profile schema subset without external packages.

    The owner-approved v1 schema uses only local references, object/array/scalar
    types, required/additionalProperties, const/enum, numeric/string limits,
    patterns, uniqueItems and simple if/then clauses. Unsupported schema
    constructs fail closed rather than being ignored.
    """
    supported = {
        "$schema", "$id", "$defs", "$ref", "title", "description", "type",
        "properties", "required", "additionalProperties", "const", "enum",
        "pattern", "minLength", "maxLength", "minimum", "maximum", "items",
        "minItems", "uniqueItems", "allOf", "if", "then",
    }
    def check_keywords(item: Any) -> None:
        if isinstance(item, Mapping):
            unknown = set(item) - supported
            if unknown:
                raise ProfileFailure("PROFILE_SCHEMA_INVALID", f"unsupported schema keywords: {sorted(unknown)}")
            for key, child in item.items():
                if key in {"properties", "$defs"} and isinstance(child, Mapping):
                    for sub in child.values():
                        check_keywords(sub)
                elif key not in {"properties", "$defs"}:
                    check_keywords(child)
        elif isinstance(item, list):
            for child in item:
                check_keywords(child)
    check_keywords(schema)
    errors = sorted(_schema_issues(profile, schema, schema), key=lambda err: (err.absolute_path, err.message))
    if errors:
        first = errors[0]
        raise ProfileFailure(_jsonschema_error_to_reason(first), first.message)


def _validate_identity(profile: Mapping[str, Any]) -> None:
    profile_id = profile.get("profile_id")
    profile_version = profile.get("profile_version")
    if not isinstance(profile_id, str) or not PROFILE_ID_RE.fullmatch(profile_id):
        raise ProfileFailure("PROFILE_ID_OR_VERSION_INVALID", "profile_id")
    if not isinstance(profile_version, str) or not PROFILE_VERSION_RE.fullmatch(profile_version):
        raise ProfileFailure("PROFILE_ID_OR_VERSION_INVALID", "profile_version")


def _validate_serial_selector_structure(selector: Mapping[str, Any]) -> None:
    strategy = selector.get("strategy")
    value = selector.get("value")
    if selector.get("allow_fallback") is not False or selector.get("required_unique") is not True:
        raise ProfileFailure("SERIAL_WILDCARD_OR_FALLBACK_FORBIDDEN")
    if not isinstance(value, str) or "*" in value or "?" in value:
        raise ProfileFailure("SERIAL_WILDCARD_OR_FALLBACK_FORBIDDEN")
    patterns = {
        "explicit_path": SAFE_EXPLICIT_SERIAL_RE,
        "linux_by_id": SAFE_BY_ID_RE,
        "linux_by_path": SAFE_BY_PATH_RE,
        "synthetic": SAFE_SYNTHETIC_RE,
    }
    pattern = patterns.get(str(strategy))
    if pattern is None or not pattern.fullmatch(value):
        raise ProfileFailure("SERIAL_PATH_UNSAFE", str(value))
    if strategy != "synthetic":
        pure = PurePosixPath(value)
        if not pure.is_absolute() or ".." in pure.parts:
            raise ProfileFailure("SERIAL_PATH_UNSAFE", str(value))


def _validate_gpio(profile: Mapping[str, Any]) -> None:
    backend = profile.get("gpio_backend", {}).get("adapter_id")
    numbering = profile.get("gpio_numbering")
    pins = profile.get("gpio_pins", {})
    if backend == "rpi-gpio-v1" and numbering != "BCM":
        raise ProfileFailure("GPIO_BACKEND_UNSUPPORTED", "rpi-gpio-v1 requires BCM")
    if backend == "synthetic-gpio-v1" and numbering != "SYNTHETIC":
        raise ProfileFailure("GPIO_BACKEND_UNSUPPORTED", "synthetic-gpio-v1 requires SYNTHETIC")
    if backend not in {"rpi-gpio-v1", "synthetic-gpio-v1"}:
        raise ProfileFailure("GPIO_BACKEND_UNSUPPORTED", str(backend))
    if pins.get("m0") == pins.get("m1"):
        raise ProfileFailure("GPIO_PIN_COLLISION")


def _validate_uart(profile: Mapping[str, Any]) -> None:
    if profile.get("uart_baudrate") != 9600:
        raise ProfileFailure("UART_BAUDRATE_UNSUPPORTED")


def _validate_capability_declaration(profile: Mapping[str, Any]) -> None:
    values = profile.get("capabilities")
    if not isinstance(values, list) or not values:
        raise ProfileFailure("CAPABILITY_INVALID")
    if len(values) != len(set(values)) or any(value not in PROFILE_CAPABILITIES for value in values):
        raise ProfileFailure("CAPABILITY_INVALID")


def _validate_service_contract(profile: Mapping[str, Any]) -> None:
    contract = profile.get("service_contract")
    if contract is None:
        return
    if not isinstance(contract, Mapping):
        raise ProfileFailure("SERVICE_CONTRACT_INCOMPATIBLE")
    if contract.get("api_bind") != "127.0.0.1":
        raise ProfileFailure("NETWORK_EXPOSURE_FORBIDDEN")
    if dict(contract) != LEGACY_SERVICE_CONTRACT:
        raise ProfileFailure("SERVICE_CONTRACT_INCOMPATIBLE")


def _validate_paths(profile: Mapping[str, Any]) -> None:
    paths = profile.get("paths")
    if paths is None:
        return
    if not isinstance(paths, Mapping) or dict(paths) != LEGACY_PATHS:
        raise ProfileFailure("DATA_PATH_MUTATION_OUT_OF_SCOPE")


def _validate_security_flags(profile: Mapping[str, Any]) -> None:
    security = profile.get("security")
    if not isinstance(security, Mapping):
        raise ProfileFailure("PROFILE_REQUIRED_FIELD_MISSING", "security")
    if security.get("allow_role_change") is not False:
        raise ProfileFailure("ROLE_CHANGE_FORBIDDEN")
    if security.get("allow_secret_fields") is not False:
        raise ProfileFailure("SECRET_FIELD_FORBIDDEN")
    if security.get("allow_radio_parameter_changes") is not False:
        raise ProfileFailure("RADIO_PARAMETER_CHANGE_FORBIDDEN")
    if security.get("allow_autodetect") is not False or security.get("local_only") is not True:
        raise ProfileFailure("AUTODETECT_OR_NETWORK_FORBIDDEN")


def _validate_support_class(
    profile: Mapping[str, Any],
    approved_support_registry: Mapping[tuple[str, str], Mapping[str, Any]] | None,
) -> None:
    support_class = profile.get("support_class")
    if support_class not in {
        "TESTED_REFERENCE",
        "VERIFIED_PROFILE",
        "EXPERIMENTAL",
        "UNTESTED",
        "INCOMPATIBLE",
    }:
        raise ProfileFailure("SUPPORT_CLASS_INVALID")
    if support_class not in {"TESTED_REFERENCE", "VERIFIED_PROFILE"}:
        return
    registry = approved_support_registry or {}
    key = (str(profile.get("profile_id")), str(profile.get("profile_version")))
    approved = registry.get(key)
    if not approved:
        raise ProfileFailure("SUPPORT_CLASS_ESCALATION")
    if approved.get("support_class") != support_class:
        raise ProfileFailure("SUPPORT_CLASS_ESCALATION")
    expected_sha = approved.get("canonical_sha256")
    if expected_sha:
        normalized = copy.deepcopy(dict(profile))
        actual_sha = sha256_bytes(canonical_json_bytes(normalized))
        if actual_sha != expected_sha:
            raise ProfileFailure("SUPPORT_CLASS_ESCALATION", "profile identity differs from approved evidence")


def validate_profile(
    raw_profile: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    program_version: str,
    approved_support_registry: Mapping[tuple[str, str], Mapping[str, Any]] | None = None,
) -> ValidatedProfile:
    """Validate and deterministically normalize a hardware profile."""
    if not isinstance(raw_profile, Mapping):
        raise ProfileFailure("PROFILE_ROOT_INVALID")
    profile = copy.deepcopy(dict(raw_profile))
    _reject_forbidden_profile_fields(profile)
    _validate_schema(profile, schema)
    _validate_identity(profile)
    _validate_serial_selector_structure(profile["serial_selector"])
    _validate_gpio(profile)
    _validate_uart(profile)
    _validate_capability_declaration(profile)
    _validate_service_contract(profile)
    _validate_paths(profile)
    _validate_security_flags(profile)
    if not isinstance(program_version, str) or not program_version.strip():
        raise ProfileFailure("PRODUCT_VERSION_REQUIRED")
    program_version = program_version.strip()
    if program_version not in profile.get("tested_product_versions", []):
        raise ProfileFailure("PRODUCT_VERSION_INCOMPATIBLE", program_version)
    registry = approved_support_registry or {}
    key = (str(profile.get("profile_id")), str(profile.get("profile_version")))
    registered = registry.get(key)
    if registered and registered.get("canonical_sha256"):
        actual_sha = sha256_bytes(canonical_json_bytes(profile))
        if actual_sha != registered["canonical_sha256"]:
            raise ProfileFailure("PROFILE_IDENTITY_MISMATCH")
    _validate_support_class(profile, registry)
    canonical = canonical_json_bytes(profile)
    return ValidatedProfile(
        profile=profile,
        canonical_json=canonical,
        canonical_sha256=sha256_bytes(canonical),
    )


def validate_profile_fail_closed(
    raw_profile: Mapping[str, Any],
    schema: Mapping[str, Any],
    **kwargs: Any,
) -> ValidationOutcome:
    """Return a stable failure outcome for parser, validator, or adapter errors."""
    try:
        validated = validate_profile(raw_profile, schema, **kwargs)
    except ProfileFailure as exc:
        return ValidationOutcome(False, (exc.reason_code,), exc.detail)
    except Exception as exc:  # fail closed for unexpected prototype errors
        return ValidationOutcome(False, ("ADAPTER_EXCEPTION",), f"{type(exc).__name__}: {exc}")
    return ValidationOutcome(
        True,
        validated.reason_codes,
        normalized_profile=validated.profile,
        canonical_sha256=validated.canonical_sha256,
    )


def normalize_role(role: Any) -> str:
    text = str(role or "").strip().lower()
    if text in CANONICAL_ROLES:
        return text
    if text in ROLE_ALIASES:
        return ROLE_ALIASES[text]
    raise ProfileFailure("ROLE_INVALID", repr(role))


def validate_binding(binding: Mapping[str, Any], profile: Mapping[str, Any]) -> dict[str, Any]:
    """Validate an explicit deployment binding without role inference or mutation."""
    allowed_fields = {
        "binding_id",
        "hardware_profile_id",
        "hardware_profile_version",
        "role",
        "enabled_capabilities",
        "legacy_fallback_allowed",
    }
    unknown = set(binding) - allowed_fields
    if unknown & ROLE_MUTATION_FIELD_NAMES or unknown & {"discovered_role", "profile_role"}:
        raise ProfileFailure("ROLE_CHANGE_FORBIDDEN", ",".join(sorted(unknown)))
    if unknown:
        raise ProfileFailure("BINDING_UNKNOWN_FIELD", ",".join(sorted(unknown)))

    role = normalize_role(binding.get("role"))
    if binding.get("hardware_profile_id") != profile.get("profile_id"):
        raise ProfileFailure("PROFILE_BINDING_ID_MISMATCH")
    if binding.get("hardware_profile_version") != profile.get("profile_version"):
        raise ProfileFailure("PROFILE_BINDING_VERSION_MISMATCH")

    enabled = binding.get("enabled_capabilities")
    if not isinstance(enabled, list) or len(enabled) != len(set(enabled)):
        raise ProfileFailure("CAPABILITY_INVALID")
    if any(item not in PROFILE_CAPABILITIES for item in enabled):
        raise ProfileFailure("CAPABILITY_INVALID")
    available = set(profile.get("capabilities", []))
    if not set(enabled).issubset(available):
        raise ProfileFailure("CAPABILITY_NOT_AVAILABLE")
    if not set(enabled).issubset(ROLE_CAPABILITY_POLICY[role]):
        raise ProfileFailure("CAPABILITY_NOT_PERMITTED_FOR_ROLE")

    return {
        "binding_id": str(binding.get("binding_id", "")),
        "hardware_profile_id": str(profile.get("profile_id")),
        "hardware_profile_version": str(profile.get("profile_version")),
        "role": role,
        "enabled_capabilities": sorted(enabled),
        "legacy_fallback_allowed": bool(binding.get("legacy_fallback_allowed", False)),
    }


def resolve_serial_selector(
    selector: Mapping[str, Any],
    synthetic_resolution_map: Mapping[str, Sequence[str]],
) -> str:
    """Resolve one declared selector against a synthetic, read-only fixture map."""
    _validate_serial_selector_structure(selector)
    value = str(selector["value"])
    try:
        candidates = list(synthetic_resolution_map.get(value, ()))
    except Exception as exc:
        raise ProfileFailure("SERIAL_RESOLUTION_FAILED", f"{type(exc).__name__}: {exc}") from exc
    unique = sorted(set(str(item) for item in candidates))
    if not unique:
        raise ProfileFailure("SERIAL_TARGET_MISSING", value)
    if len(unique) != 1:
        raise ProfileFailure("SERIAL_TARGET_AMBIGUOUS", value)
    target = unique[0]
    if not target.startswith("/dev/") and not target.startswith("synthetic:"):
        raise ProfileFailure("SERIAL_PATH_UNSAFE", target)
    return target


def validate_required_groups(required_groups: Sequence[str], present_groups: Iterable[str]) -> None:
    present = set(present_groups)
    missing = sorted(set(required_groups) - present)
    if missing:
        raise ProfileFailure("REQUIRED_GROUP_MISSING", ",".join(missing))


def validate_runtime_paths(
    runtime: Mapping[str, str],
    synthetic_executable_map: Mapping[str, bool],
) -> None:
    for key in ("main_interpreter", "meshtastic_interpreter"):
        path = runtime.get(key)
        if not isinstance(path, str) or not synthetic_executable_map.get(path, False):
            raise ProfileFailure("RUNTIME_INTERPRETER_INVALID", str(path))


def compare_hash_snapshots(before: Mapping[str, str], after: Mapping[str, str]) -> None:
    if dict(before) != dict(after):
        raise ProfileFailure("DATA_OR_MAP_MUTATED")


def compare_protocol_snapshot(before: Mapping[str, Any], after: Mapping[str, Any]) -> None:
    if canonical_json_bytes(before) != canonical_json_bytes(after):
        raise ProfileFailure("PROTOCOL_INVARIANT_CHANGED")


def reference_semantic_snapshot(profile: Mapping[str, Any]) -> dict[str, Any]:
    """Translate the reference profile to the documented legacy semantics."""
    service = profile.get("service_contract", {})
    paths = profile.get("paths", {})
    runtime = profile.get("python_runtime", {})
    pins = profile.get("gpio_pins", {})
    return {
        "serial_port": profile.get("serial_selector", {}).get("value"),
        "uart_baudrate": profile.get("uart_baudrate"),
        "gpio_numbering": profile.get("gpio_numbering"),
        "gpio_m0": pins.get("m0"),
        "gpio_m1": pins.get("m1"),
        "main_interpreter": runtime.get("main_interpreter"),
        "meshtastic_interpreter": runtime.get("meshtastic_interpreter"),
        "required_groups": sorted(profile.get("required_groups", [])),
        **dict(service),
        **dict(paths),
    }


def assert_reference_semantic_compatibility(profile: Mapping[str, Any]) -> None:
    snapshot = reference_semantic_snapshot(profile)
    expected = dict(REFERENCE_SEMANTICS)
    expected["required_groups"] = sorted(expected["required_groups"])
    if snapshot != expected:
        raise ProfileFailure("REFERENCE_SEMANTICS_INCOMPATIBLE")


def diagnostics_profile_view(
    profile: Mapping[str, Any],
    reason_codes: Sequence[str],
) -> dict[str, Any]:
    """Return only the privacy-reduced profile view allowed by PORT-K1."""
    return {
        "profile_id": str(profile.get("profile_id", "")),
        "profile_version": str(profile.get("profile_version", "")),
        "support_class": str(profile.get("support_class", "")),
        "capabilities": sorted(str(item) for item in profile.get("capabilities", [])),
        "reason_codes": list(reason_codes),
    }


def validate_privacy_reduced_report(report: Mapping[str, Any]) -> None:
    allowed = {
        "profile_id",
        "profile_version",
        "support_class",
        "capabilities",
        "reason_codes",
    }
    unknown = set(report) - allowed
    if unknown:
        raise ProfileFailure("PRIVACY_REDUCTION_REQUIRED", ",".join(sorted(unknown)))
    for parent, key, _value in _walk_object(report):
        if key.strip().lower() in PRIVACY_FORBIDDEN_FIELD_NAMES:
            raise ProfileFailure("PRIVACY_REDUCTION_REQUIRED", ".".join(parent + (key,)))


def legacy_reference_path(config: Mapping[str, Any]) -> dict[str, Any]:
    """Preserve the legacy path when no profile is configured."""
    if config.get("hardware_profile") or config.get("hardware_profile_path"):
        raise ProfileFailure("PROFILE_EXPLICITLY_CONFIGURED")
    return {
        "status": "LEGACY_REFERENCE_PATH",
        "write_performed": False,
        "migration_performed": False,
    }


def approved_reference_registry(
    reference_profiles: Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """Build an immutable local identity registry from explicit profile objects."""
    if isinstance(reference_profiles, Mapping):
        profiles: Sequence[Mapping[str, Any]] = (reference_profiles,)
    else:
        profiles = tuple(reference_profiles)
    registry: dict[tuple[str, str], dict[str, Any]] = {}
    for profile in profiles:
        profile_id = str(profile.get("profile_id", ""))
        profile_version = str(profile.get("profile_version", ""))
        if not profile_id or not profile_version:
            raise ProfileFailure("PROFILE_ID_OR_VERSION_INVALID")
        key = (profile_id, profile_version)
        if key in registry:
            raise ProfileFailure("PROFILE_REGISTRY_DUPLICATE", f"{profile_id}@{profile_version}")
        registry[key] = {
            "support_class": str(profile.get("support_class", "")),
            "canonical_sha256": sha256_bytes(canonical_json_bytes(profile)),
            "evidence": "explicit immutable candidate-owned profile registry",
        }
    return registry


def physical_proof_boundary(validated: ValidatedProfile) -> dict[str, Any]:
    """State the synthetic proof boundary without escalating physical support."""
    return {
        "synthetic_validation": "PASS",
        "profile_id": validated.profile["profile_id"],
        "declared_support_class": validated.profile["support_class"],
        "verified_profile_granted": False,
        "device_contact_authorized": False,
        "installation_authorized": False,
    }
