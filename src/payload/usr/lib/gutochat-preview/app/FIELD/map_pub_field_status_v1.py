"""Pure Field presentation policy for host-proxy-aware MAP_PUB status."""
from __future__ import annotations
from typing import Any


def host_proxy_managed(status: dict[str, Any] | None) -> bool:
    value = dict(status or {})
    reason = str(value.get("reason_code", "")).upper()
    return value.get("verified") is True and reason.startswith("HOST_PROXY_")


def map_action_policy(
    *,
    enabled: bool,
    sequence_active: bool,
    map_status: dict[str, Any],
    map_view: dict[str, Any],
) -> tuple[bool, str]:
    """Return (button_enabled, i18n_key) without performing any write."""
    managed = host_proxy_managed(map_status)
    state = str(map_status.get("state", "UNKNOWN_DEGRADED")).upper()
    if enabled and not sequence_active and state in {"ON", "OFF"}:
        return True, (
            "system.map_publication.action.deactivate"
            if state == "ON"
            else "system.map_publication.action.activate"
        )
    if enabled and not sequence_active and map_view.get("stale"):
        return False, "system.map_publication.action.stale"
    return False, "system.map_publication.action.unavailable"


def remote_detail_key(status: dict[str, Any], resource: str) -> str:
    if status.get("fresh"):
        if str(resource).upper() == "MAP_PUB":
            reason = str(status.get("reason_code", "")).upper()
            mapping = {
                "HOST_PROXY_NOT_ARMED": "system.remote_base_status.detail.map_host_proxy_not_armed",
                "HOST_PROXY_ARMED_READY": "system.remote_base_status.detail.map_host_proxy_armed_ready",
                "HOST_PROXY_CONSUMER_DISCONNECTED": "system.remote_base_status.detail.map_host_proxy_disconnected",
                "HOST_PROXY_NO_PUBLICATION_PATH": "system.remote_base_status.detail.map_host_proxy_no_path",
            }
            if reason in mapping:
                return mapping[reason]
        return "system.remote_base_status.detail.verified"
    if status.get("stale"):
        return "system.remote_base_status.detail.stale"
    return "system.remote_base_status.detail.unknown"
