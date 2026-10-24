"""C5.7 fixed-command transport from unprivileged GUI to root-owned helper."""
from __future__ import annotations

import os
import subprocess
from typing import Any

from aprs_igate_control_client_v1 import fail_closed_status, safe_parse_or_unknown

SUDO = "/usr/bin/sudo"
HELPER = "/usr/local/libexec/gutochat-aprs-igate-control-v1"
ALLOWED_OPERATIONS = frozenset({"status", "activate", "deactivate"})
SAFE_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


def run_operation(operation: str, *, timeout: float | None = None) -> dict[str, Any]:
    if operation not in ALLOWED_OPERATIONS:
        return fail_closed_status("C5_7_3_OPERATION_REJECTED")
    default_timeouts = {
        "status": 20.0,
        "activate": 180.0,
        "deactivate": 45.0,
    }
    max_timeouts = {
        "status": 60.0,
        "activate": 180.0,
        "deactivate": 60.0,
    }
    limit = float(timeout if timeout is not None else default_timeouts[operation])
    if not (0.5 <= limit <= max_timeouts[operation]):
        return fail_closed_status("C5_7_3_TIMEOUT_REJECTED")
    try:
        cp = subprocess.run(
            [SUDO, "-n", HELPER, operation],
            input=None,
            capture_output=True,
            check=False,
            timeout=limit,
            env=SAFE_ENV,
        )
    except (OSError, subprocess.SubprocessError):
        return fail_closed_status("C5_7_3_HELPER_EXECUTION_FAILED")
    # stderr is intentionally never surfaced into the GUI/parser.
    result = safe_parse_or_unknown(cp.stdout)
    if result.get("operation") != operation:
        return fail_closed_status("C5_7_3_OPERATION_RESULT_MISMATCH")
    return result


def read_status() -> dict[str, Any]:
    result = run_operation("status")
    if result.get("operation") != "status":
        return fail_closed_status("C5_7_3_NON_STATUS_RESULT_REJECTED")
    state = result.get("state")
    if state == "OFF":
        if not (
            result.get("ok") is True
            and result.get("changed") is False
            and result.get("result_code") == "STATUS_OFF"
            and isinstance(result.get("can_activate"), bool)
        ):
            return fail_closed_status("C5_7_3_OFF_CONTRACT_MISMATCH")
    elif state == "ON":
        if not (
            result.get("ok") is True
            and result.get("changed") is False
            and result.get("result_code") == "STATUS_ON"
            and result.get("can_activate") is False
        ):
            return fail_closed_status("C5_7_3_ON_CONTRACT_MISMATCH")
    return result


def activate() -> dict[str, Any]:
    return run_operation("activate")


def deactivate() -> dict[str, Any]:
    return run_operation("deactivate")
