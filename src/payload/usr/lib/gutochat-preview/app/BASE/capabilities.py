"""Capability policy helpers for profile-aware GuToChat runtime surfaces.

The beta4 legacy path remains permissive for compatibility.  Capability
*enforcement* starts only when ``hardware_profile_runtime`` metadata is present,
which is produced by the validated hardware-profile boundary.
"""
from __future__ import annotations

from typing import Any, Mapping

from hardware_profile import PROFILE_CAPABILITIES

CAPABILITY_ORDER = (
    "private_lora",
    "meshtastic_local_868",
    "meshtastic_local_433",
    "meshtastic_gateway_descriptors",
    "gnss",
    "gui",
    "diagnostics",
)


def runtime_capability_view(config: Mapping[str, Any]) -> dict[str, Any]:
    """Return a presentation-safe capability view for one resolved config.

    No hardware discovery is performed.  When no validated hardware profile is
    active, the view is explicitly marked ``legacy`` and capabilities are not
    enforced so existing beta4 configs keep their historical behavior.
    """
    runtime = config.get("_hardware_profile_runtime")
    if isinstance(runtime, Mapping):
        enabled_raw = runtime.get("enabled_capabilities", [])
        enabled = {
            str(item)
            for item in enabled_raw
            if isinstance(item, str) and item in PROFILE_CAPABILITIES
        }
        return {
            "mode": "profile",
            "enforced": True,
            "enabled": tuple(item for item in CAPABILITY_ORDER if item in enabled),
            "disabled": tuple(item for item in CAPABILITY_ORDER if item not in enabled),
            "profile_id": str(runtime.get("profile_id", "")),
            "profile_version": str(runtime.get("profile_version", "")),
            "support_class": str(runtime.get("support_class", "")),
        }
    return {
        "mode": "legacy",
        "enforced": False,
        "enabled": (),
        "disabled": (),
        "profile_id": "",
        "profile_version": "",
        "support_class": "",
    }


def capability_enabled(config: Mapping[str, Any], capability: str) -> bool:
    """Return whether a capability may be used by this runtime config.

    Legacy beta4 configs intentionally remain permissive.  A validated profile
    binding is fail-closed: only explicitly enabled capabilities are allowed.
    """
    if capability not in PROFILE_CAPABILITIES:
        return False
    view = runtime_capability_view(config)
    if not view["enforced"]:
        return True
    return capability in view["enabled"]


def required_network_capability(kind: str, item: Mapping[str, Any] | None = None) -> str | None:
    """Map a configured network descriptor to its hardware capability.

    Local Meshtastic descriptors may state ``capability`` explicitly.  For
    existing beta4 configs, route/label/API-port hints preserve compatibility.
    Unknown local-radio descriptors are intentionally unmapped so a profile-
    enforced runtime can refuse to assume hardware support.
    """
    if kind == "waveshare":
        return "private_lora"
    if kind == "mesh_gateway":
        return "meshtastic_gateway_descriptors"
    if kind != "mesh_local":
        return None

    data = item or {}
    explicit = str(data.get("capability") or "").strip()
    if explicit in {"meshtastic_local_868", "meshtastic_local_433"}:
        return explicit
    try:
        api_port = int(data.get("api_port", 0))
    except (TypeError, ValueError):
        api_port = 0
    if api_port == 8766:
        return "meshtastic_local_868"
    if api_port == 8767:
        return "meshtastic_local_433"
    hint = " ".join(
        str(data.get(key) or "") for key in ("route_key", "key", "label")
    ).casefold()
    if "868" in hint:
        return "meshtastic_local_868"
    if "433" in hint:
        return "meshtastic_local_433"
    return None


def network_capability_allowed(
    config: Mapping[str, Any], kind: str, item: Mapping[str, Any] | None = None
) -> tuple[bool, str | None]:
    """Return ``(allowed, required_capability)`` for one network descriptor."""
    required = required_network_capability(kind, item)
    view = runtime_capability_view(config)
    if required is None:
        return (not view["enforced"], None)
    return capability_enabled(config, required), required
