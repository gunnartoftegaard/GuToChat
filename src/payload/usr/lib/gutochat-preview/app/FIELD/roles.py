"""Role normalization helpers for base and field stations."""
from __future__ import annotations

from typing import Any

ROLE_BASE = "base"
ROLE_FIELD = "field"
LEGACY_ROLE_MOBILE = "mobile"
CANONICAL_ROLES = {ROLE_BASE, ROLE_FIELD}
LEGACY_ROLE_ALIASES = {LEGACY_ROLE_MOBILE: ROLE_FIELD}

_ROLE_DISPLAY = {
    "nb": {
        ROLE_BASE: "Base-stasjon",
        ROLE_FIELD: "Feltstasjon",
        LEGACY_ROLE_MOBILE: "Feltstasjon",
    },
    "en": {
        ROLE_BASE: "Base Station",
        ROLE_FIELD: "Field Station",
        LEGACY_ROLE_MOBILE: "Field Station",
    },
}


def normalize_role(value: Any, config: dict[str, Any] | None = None) -> str:
    """Return the canonical role for a config value.

    ``mobile`` is accepted as a legacy alias for ``field``.  When no explicit
    role is present, the beta4 fallback is preserved: configs with local
    Meshtastic radios are treated as ``base`` and others as ``field``.
    """
    text = str(value or "").strip().lower()
    if text in CANONICAL_ROLES:
        return text
    if text in LEGACY_ROLE_ALIASES:
        return LEGACY_ROLE_ALIASES[text]
    if text:
        raise ValueError(f"Unknown station role: {value!r}")
    if config and config.get("meshtastic_radios"):
        return ROLE_BASE
    return ROLE_FIELD


def is_legacy_role(value: Any) -> bool:
    """Return true when a role value is accepted only for compatibility."""
    return str(value or "").strip().lower() in LEGACY_ROLE_ALIASES


def role_display_name(role: Any, language: str = "nb") -> str:
    """Return a translated display name for a canonical or legacy role."""
    normalized = normalize_role(role)
    catalog = _ROLE_DISPLAY.get(language, _ROLE_DISPLAY["en"])
    return catalog.get(normalized, normalized)


def infer_role_from_config(config: dict[str, Any]) -> str:
    """Infer the canonical station role from explicit config or beta4 fallback."""
    return normalize_role(config.get("role"), config)
