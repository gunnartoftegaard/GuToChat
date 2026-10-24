"""Pure host-proxy-aware MAP_PUB readback derivation for remote Field status."""
from __future__ import annotations
from typing import Any


def _unknown(reason: str, identity_match: Any = None) -> dict[str, Any]:
    return {
        "state": "UNKNOWN_DEGRADED",
        "verified": False,
        "identity_match": identity_match,
        "reason_code": reason,
    }


def derive_remote_map_status(
    device_status: dict[str, Any],
    transport_status: dict[str, Any],
    host_runtime_status: dict[str, Any] | None,
) -> dict[str, Any]:
    """Derive the externally effective map-publication state.

    DEVICE_DIRECT/NONE retain the legacy device-MQTT semantics.  HOST_PROXY is
    ON only when the device policy/path, proxy transport/feed and host process
    arm are all verified ready.  A verified unarmed host is reported OFF.
    """
    device = dict(device_status or {})
    transport = dict(transport_status or {})
    identity_match = transport.get("identity_match", device.get("identity_match"))

    if transport.get("state_fresh") is not True:
        return _unknown("HOST_PROXY_TRANSPORT_STATUS_UNVERIFIED", identity_match)
    if identity_match is False:
        return _unknown("HOST_PROXY_IDENTITY_MISMATCH", False)

    owner = str(transport.get("transport_owner", "UNKNOWN")).upper()
    if owner in {"DEVICE_DIRECT", "NONE"}:
        # Exact compatibility path: preserve existing publication_status result.
        return device
    if owner != "HOST_PROXY":
        return _unknown("HOST_PROXY_TRANSPORT_OWNER_UNKNOWN", identity_match)

    path = transport.get("publication_path_configured")
    if path is False:
        return {
            "state": "OFF",
            "verified": True,
            "identity_match": identity_match,
            "reason_code": "HOST_PROXY_NO_PUBLICATION_PATH",
        }
    if path is not True:
        return _unknown("HOST_PROXY_PUBLICATION_PATH_UNVERIFIED", identity_match)

    if transport.get("feed_consumer_connected") is not True:
        return {
            "state": "OFF",
            "verified": True,
            "identity_match": identity_match,
            "reason_code": "HOST_PROXY_CONSUMER_DISCONNECTED",
        }

    host = dict(host_runtime_status or {})
    if host.get("verified") is not True:
        return _unknown(
            "HOST_PROXY_RUNTIME_STATUS_UNVERIFIED:" + str(host.get("reason_code") or "UNKNOWN"),
            identity_match,
        )
    if host.get("armed") is not True:
        return {
            "state": "OFF",
            "verified": True,
            "identity_match": identity_match,
            "reason_code": "HOST_PROXY_NOT_ARMED",
        }

    return {
        "state": "ON",
        "verified": True,
        "identity_match": identity_match,
        "reason_code": "HOST_PROXY_ARMED_READY",
    }
