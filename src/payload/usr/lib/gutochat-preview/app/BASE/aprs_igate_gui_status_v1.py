"""C5.7.2 read-only GUI adapter for receive-iGate control status.

This module intentionally has no subprocess, sudo, systemctl, socket, or mutable
filesystem backend.  A future separately authorized gate may supply a fixed
read-only status reader.  Without one, status fails closed to
UNKNOWN_DEGRADED.
"""
from __future__ import annotations

from collections.abc import Callable

from aprs_igate_control_client_v1 import fail_closed_status, safe_parse_or_unknown

RawStatusReader = Callable[[], bytes]


def read_status_read_only(raw_reader: RawStatusReader | None = None) -> dict[str, object]:
    """Read and validate a status result without granting any live control path."""
    if raw_reader is None:
        return fail_closed_status("C5_7_2_STATUS_SOURCE_NOT_AUTHORIZED")
    try:
        raw = raw_reader()
    except Exception:
        return fail_closed_status("C5_7_2_STATUS_SOURCE_READ_FAILED")
    result = safe_parse_or_unknown(raw)
    if result.get("operation") != "status":
        return fail_closed_status("C5_7_2_NON_STATUS_RESULT_REJECTED")
    state = result.get("state")
    if state == "OFF":
        if not (
            result.get("ok") is True
            and result.get("changed") is False
            and result.get("result_code") == "STATUS_OFF"
            and isinstance(result.get("can_activate"), bool)
        ):
            return fail_closed_status("C5_7_2_OFF_CONTRACT_MISMATCH")
    elif state == "ON":
        if not (
            result.get("ok") is True
            and result.get("changed") is False
            and result.get("result_code") == "STATUS_ON"
            and result.get("can_activate") is False
        ):
            return fail_closed_status("C5_7_2_ON_CONTRACT_MISMATCH")
    return result
