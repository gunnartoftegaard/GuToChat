"""Privacy-safe C5.7 control-helper result parser; no process execution in C5.7.1."""
from __future__ import annotations
import json
from typing import Any

SCHEMA = "gutochat.aprs.igate.control.v1"
MAX_HELPER_OUTPUT_BYTES = 65536
ALLOWED_STATES = {"OFF", "ON", "UNKNOWN_DEGRADED"}
ALLOWED_OPERATIONS = {"status", "activate", "deactivate"}


def parse_helper_output(raw: bytes, *, max_bytes: int = MAX_HELPER_OUTPUT_BYTES) -> dict[str, Any]:
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("HELPER_OUTPUT_NOT_BYTES")
    if len(raw) == 0:
        raise ValueError("HELPER_OUTPUT_EMPTY")
    if len(raw) > max_bytes:
        raise ValueError("HELPER_OUTPUT_TOO_LARGE")
    try:
        text = bytes(raw).decode("utf-8", errors="strict")
        obj = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("HELPER_OUTPUT_INVALID_JSON") from exc
    if not isinstance(obj, dict):
        raise ValueError("HELPER_OUTPUT_NOT_OBJECT")
    if obj.get("schema") != SCHEMA:
        raise ValueError("HELPER_SCHEMA_MISMATCH")
    if obj.get("operation") not in ALLOWED_OPERATIONS:
        raise ValueError("HELPER_OPERATION_INVALID")
    if obj.get("state") not in ALLOWED_STATES:
        raise ValueError("HELPER_STATE_INVALID")
    if not isinstance(obj.get("ok"), bool) or not isinstance(obj.get("changed"), bool):
        raise ValueError("HELPER_BOOLEAN_FIELDS_INVALID")
    if not isinstance(obj.get("result_code"), str) or not obj["result_code"]:
        raise ValueError("HELPER_RESULT_CODE_INVALID")
    return obj


def fail_closed_status(reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "operation": "status",
        "ok": False,
        "state": "UNKNOWN_DEGRADED",
        "state_reason": str(reason)[:160],
        "changed": False,
        "result_code": "GUI_HELPER_RESULT_INVALID",
    }


def safe_parse_or_unknown(raw: bytes) -> dict[str, Any]:
    try:
        return parse_helper_output(raw)
    except ValueError as exc:
        return fail_closed_status(str(exc))
