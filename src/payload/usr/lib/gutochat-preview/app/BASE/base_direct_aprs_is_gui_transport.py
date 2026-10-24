from __future__ import annotations

import json
import subprocess
from typing import Any, Mapping, Sequence

from base_direct_aprs_is_control import (
    DirectAprsIsPolicy,
    DirectAprsIsSnapshot,
    SERVICE,
)

HELPER = "/usr/local/libexec/gutochat-base-direct-aprs-is-control"
SUDO = "/usr/bin/sudo"
ALLOWED_ACTIONS = frozenset({"status", "on", "off"})


class BaseDirectAprsIsBackendError(RuntimeError):
    pass


def _argv(action: str) -> tuple[str, ...]:
    if action not in ALLOWED_ACTIONS:
        raise BaseDirectAprsIsBackendError("unsupported_action")
    return (SUDO, "-n", HELPER, action)


def _run(
    action: str,
    *,
    runner=subprocess.run,
    timeout: float = 35.0,
) -> dict[str, Any]:
    try:
        cp = runner(
            _argv(action),
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except Exception as exc:
        raise BaseDirectAprsIsBackendError("helper_exec_failed") from exc

    if cp.returncode != 0:
        raise BaseDirectAprsIsBackendError("helper_nonzero")
    try:
        data = json.loads(cp.stdout)
    except Exception as exc:
        raise BaseDirectAprsIsBackendError("helper_invalid_json") from exc
    if not isinstance(data, dict):
        raise BaseDirectAprsIsBackendError("helper_invalid_reply")
    if data.get("service") != SERVICE:
        raise BaseDirectAprsIsBackendError("helper_wrong_service")
    return data


def _snapshot_from_helper_mapping(data: Mapping[str, object]) -> DirectAprsIsSnapshot:
    policy_obj = data.get("policy")
    headless_obj = data.get("headless")
    if not isinstance(policy_obj, Mapping):
        raise BaseDirectAprsIsBackendError("helper_policy_missing")
    if not isinstance(headless_obj, Mapping):
        raise BaseDirectAprsIsBackendError("helper_headless_missing")

    return DirectAprsIsSnapshot(
        active=bool(data.get("active", False)),
        enabled=bool(data.get("enabled", False)),
        headless_fresh=bool(headless_obj.get("fresh", False)),
        headless_running=bool(headless_obj.get("running", False)),
        headless_connected=bool(headless_obj.get("connected", False)),
        headless_error=str(headless_obj.get("error", "") or ""),
        policy=DirectAprsIsPolicy(
            receive_only=bool(policy_obj.get("receive_only", False)),
            aprs_transmit=bool(policy_obj.get("aprs_transmit", False)),
            cross_network_routing=bool(policy_obj.get("cross_network_routing", False)),
        ),
    )


def read_status(*, runner=subprocess.run) -> DirectAprsIsSnapshot:
    reply = _run("status", runner=runner, timeout=10.0)
    if reply.get("ok") is not True or reply.get("action") != "status":
        raise BaseDirectAprsIsBackendError("helper_status_failed")
    after = reply.get("after")
    if not isinstance(after, Mapping):
        raise BaseDirectAprsIsBackendError("helper_status_missing_after")
    return _snapshot_from_helper_mapping(after)


def set_enabled(target_on: bool, *, runner=subprocess.run) -> dict[str, Any]:
    action = "on" if target_on else "off"
    reply = _run(action, runner=runner, timeout=35.0)
    if reply.get("action") != action:
        raise BaseDirectAprsIsBackendError("helper_action_mismatch")
    return reply
