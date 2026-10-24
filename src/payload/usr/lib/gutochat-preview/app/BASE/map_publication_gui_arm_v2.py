#!/usr/bin/env python3
"""Fail-closed, target-bound one-shot GUI arm handling for MAP-PUB.

The root-owned arm is an authorization source.  The unprivileged GUI never
modifies it.  Instead, before any backend control call is started, the GUI
atomically records the operation id in a per-user consumed-authorizations
directory.  A second GUI invocation or GUI restart therefore treats the same
root-issued operation id as consumed.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from protocol import canonical_meshtastic_id

ARM_SCHEMA = "gutochat.map.publication.live_write_arm.v2"
CONSUMPTION_SCHEMA = "gutochat.map.publication.live_write_consumption.v2"
DISPATCH_SCHEMA = "gutochat.map.publication.live_write_dispatch.v2"
NETWORK = "mesh868"
MAX_ARM_BYTES = 4096
MAX_ARM_LIFETIME_SECONDS = 600
ARM_MODE = 0o644
STATE_DIR_MODE = 0o700
RECORD_MODE = 0o600
_REQUIRED_ARM_KEYS = {
    "schema",
    "network",
    "enabled",
    "expected_node_id",
    "target_state",
    "operation_id",
    "issued_at_utc",
    "expires_at_utc",
}


def default_consumed_dir() -> Path:
    return Path.home() / ".local/state/gutochat/map-publication-authorizations-v2"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    parsed = parsed.astimezone(timezone.utc)
    return parsed


def _canonical_operation_id(value: Any) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return ""
    if parsed.version != 4:
        return ""
    canonical = str(parsed)
    return canonical if str(value).strip().lower() == canonical else ""


def _record_path(consumed_dir: Path, operation_id: str) -> Path:
    return consumed_dir / f"{operation_id}.consumed.json"


def _dispatch_path(consumed_dir: Path, operation_id: str) -> Path:
    return consumed_dir / f"{operation_id}.dispatch.json"


def _safe_state_dir(path: Path, *, create: bool) -> bool:
    try:
        if create:
            path.mkdir(parents=True, exist_ok=True, mode=STATE_DIR_MODE)
        st = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False
    if st.st_uid != os.geteuid() or st.st_gid != os.getegid():
        return False
    # Never repair an existing directory here.  Validation remains read-only;
    # unsafe ownership/mode is a fail-closed condition.
    return stat.S_IMODE(st.st_mode) == STATE_DIR_MODE


def _read_root_arm_bytes(path: Path) -> tuple[bytes | None, str]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        return None, "ARM_MISSING_OR_UNREADABLE"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "ARM_NOT_REGULAR_FILE"
        if st.st_uid != 0 or st.st_gid != 0:
            return None, "ARM_NOT_ROOT_OWNED"
        if stat.S_IMODE(st.st_mode) != ARM_MODE:
            return None, "ARM_UNSAFE_MODE"
        if st.st_nlink != 1:
            return None, "ARM_UNSAFE_LINK_COUNT"
        if st.st_size <= 0 or st.st_size > MAX_ARM_BYTES:
            return None, "ARM_UNSAFE_SIZE"
        chunks: list[bytes] = []
        remaining = MAX_ARM_BYTES + 1
        while remaining > 0:
            part = os.read(fd, min(remaining, 4096))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        raw = b"".join(chunks)
        if len(raw) > MAX_ARM_BYTES:
            return None, "ARM_UNSAFE_SIZE"
        return raw, "OK"
    finally:
        os.close(fd)


def inspect_arm(
    path: Path,
    *,
    expected_node_id: str,
    target_state: str | None = None,
    consumed_dir: Path | None = None,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    """Validate a root-issued arm without changing any state."""
    result: dict[str, Any] = {"valid": False, "reason_code": "ARM_INVALID"}
    raw, reason = _read_root_arm_bytes(Path(path))
    if raw is None:
        result["reason_code"] = reason
        return result
    digest = hashlib.sha256(raw).hexdigest()
    try:
        arm = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, TypeError):
        result["reason_code"] = "ARM_MALFORMED_JSON"
        return result
    if not isinstance(arm, dict) or set(arm) != _REQUIRED_ARM_KEYS:
        result["reason_code"] = "ARM_SCHEMA_FIELDS_INVALID"
        return result
    if arm.get("schema") != ARM_SCHEMA:
        result["reason_code"] = "ARM_WRONG_SCHEMA"
        return result
    if arm.get("network") != NETWORK:
        result["reason_code"] = "ARM_WRONG_NETWORK"
        return result
    if arm.get("enabled") is not True:
        result["reason_code"] = "ARM_NOT_ENABLED"
        return result

    expected = canonical_meshtastic_id(str(expected_node_id).strip())
    armed_node = canonical_meshtastic_id(str(arm.get("expected_node_id", "")).strip())
    if not expected or armed_node != expected:
        result["reason_code"] = "ARM_WRONG_NODE"
        return result

    target = str(arm.get("target_state", "")).strip().upper()
    if target not in {"ON", "OFF"}:
        result["reason_code"] = "ARM_INVALID_TARGET"
        return result
    requested = str(target_state or "").strip().upper()
    if requested and requested != target:
        result["reason_code"] = "ARM_TARGET_MISMATCH"
        return result

    operation_id = _canonical_operation_id(arm.get("operation_id"))
    if not operation_id:
        result["reason_code"] = "ARM_INVALID_OPERATION_ID"
        return result

    issued = _parse_utc(arm.get("issued_at_utc"))
    expires = _parse_utc(arm.get("expires_at_utc"))
    if issued is None or expires is None or expires <= issued:
        result["reason_code"] = "ARM_INVALID_TIME_WINDOW"
        return result
    if (expires - issued).total_seconds() > MAX_ARM_LIFETIME_SECONDS:
        result["reason_code"] = "ARM_LIFETIME_TOO_LONG"
        return result
    now = (now_utc or _utc_now()).astimezone(timezone.utc)
    if now < issued:
        result["reason_code"] = "ARM_NOT_YET_VALID"
        return result
    if now > expires:
        result["reason_code"] = "ARM_EXPIRED"
        return result

    state_dir = Path(consumed_dir or default_consumed_dir())
    try:
        if state_dir.exists() and not _safe_state_dir(state_dir, create=False):
            result["reason_code"] = "CONSUMED_STATE_DIR_UNSAFE"
            return result
    except OSError:
        result["reason_code"] = "CONSUMED_STATE_UNREADABLE"
        return result
    consumed_path = _record_path(state_dir, operation_id)
    try:
        if consumed_path.exists():
            result["reason_code"] = "ARM_ALREADY_CONSUMED"
            return result
    except OSError:
        result["reason_code"] = "CONSUMED_STATE_UNREADABLE"
        return result

    result.update(
        {
            "valid": True,
            "reason_code": "ARM_VALID",
            "operation_id": operation_id,
            "target_state": target,
            "expected_node_id": expected,
            "arm_sha256": digest,
            "issued_at_utc": issued.isoformat().replace("+00:00", "Z"),
            "expires_at_utc": expires.isoformat().replace("+00:00", "Z"),
        }
    )
    return result


def consume_arm(
    path: Path,
    *,
    expected_node_id: str,
    target_state: str,
    consumed_dir: Path | None = None,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    """Atomically consume one valid arm operation before backend dispatch."""
    state_dir = Path(consumed_dir or default_consumed_dir())
    if not _safe_state_dir(state_dir, create=True):
        return {"valid": False, "reason_code": "CONSUMED_STATE_DIR_UNSAFE"}

    arm = inspect_arm(
        Path(path),
        expected_node_id=expected_node_id,
        target_state=target_state,
        consumed_dir=state_dir,
        now_utc=now_utc,
    )
    if arm.get("valid") is not True:
        return arm

    operation_id = str(arm["operation_id"])
    record_path = _record_path(state_dir, operation_id)
    consumed_at = (now_utc or _utc_now()).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    record = {
        "schema": CONSUMPTION_SCHEMA,
        "operation_id": operation_id,
        "target_state": arm["target_state"],
        "expected_node_id": arm["expected_node_id"],
        "arm_sha256": arm["arm_sha256"],
        "consumed_at_utc": consumed_at,
    }
    payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(record_path, flags, RECORD_MODE)
    except FileExistsError:
        return {"valid": False, "reason_code": "ARM_ALREADY_CONSUMED"}
    except OSError:
        return {"valid": False, "reason_code": "CONSUMPTION_RECORD_CREATE_FAILED"}
    try:
        os.write(fd, payload)
        os.fsync(fd)
        os.fchmod(fd, RECORD_MODE)
    except OSError:
        try:
            record_path.unlink()
        except OSError:
            pass
        return {"valid": False, "reason_code": "CONSUMPTION_RECORD_WRITE_FAILED"}
    finally:
        os.close(fd)

    token = dict(record)
    token["valid"] = True
    token["reason_code"] = "ARM_CONSUMED_ONE_SHOT"
    return token


def claim_dispatch(
    token: dict[str, Any],
    *,
    consumed_dir: Path | None = None,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    """Claim the already-consumed authorization exactly once for backend dispatch."""
    if not isinstance(token, dict) or token.get("valid") is not True:
        return {"claimed": False, "reason_code": "DISPATCH_TOKEN_INVALID"}
    operation_id = _canonical_operation_id(token.get("operation_id"))
    target = str(token.get("target_state", "")).strip().upper()
    expected = canonical_meshtastic_id(str(token.get("expected_node_id", "")).strip())
    digest = str(token.get("arm_sha256", "")).strip().lower()
    if not operation_id or target not in {"ON", "OFF"} or not expected or len(digest) != 64:
        return {"claimed": False, "reason_code": "DISPATCH_TOKEN_INVALID"}

    state_dir = Path(consumed_dir or default_consumed_dir())
    if not _safe_state_dir(state_dir, create=False):
        return {"claimed": False, "reason_code": "CONSUMED_STATE_DIR_UNSAFE"}
    record_path = _record_path(state_dir, operation_id)
    try:
        raw = record_path.read_text(encoding="utf-8")
        record = json.loads(raw)
    except (OSError, ValueError, TypeError):
        return {"claimed": False, "reason_code": "CONSUMPTION_RECORD_UNREADABLE"}
    if not isinstance(record, dict) or record.get("schema") != CONSUMPTION_SCHEMA:
        return {"claimed": False, "reason_code": "CONSUMPTION_RECORD_INVALID"}
    for key, value in (
        ("operation_id", operation_id),
        ("target_state", target),
        ("expected_node_id", expected),
        ("arm_sha256", digest),
    ):
        if str(record.get(key, "")).strip().lower() != str(value).strip().lower():
            return {"claimed": False, "reason_code": "CONSUMPTION_RECORD_MISMATCH"}

    dispatch_path = _dispatch_path(state_dir, operation_id)
    dispatch = {
        "schema": DISPATCH_SCHEMA,
        "operation_id": operation_id,
        "target_state": target,
        "arm_sha256": digest,
        "dispatch_started_at_utc": (now_utc or _utc_now()).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    payload = (json.dumps(dispatch, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(dispatch_path, flags, RECORD_MODE)
    except FileExistsError:
        return {"claimed": False, "reason_code": "DISPATCH_ALREADY_CLAIMED"}
    except OSError:
        return {"claimed": False, "reason_code": "DISPATCH_RECORD_CREATE_FAILED"}
    try:
        os.write(fd, payload)
        os.fsync(fd)
        os.fchmod(fd, RECORD_MODE)
    except OSError:
        try:
            dispatch_path.unlink()
        except OSError:
            pass
        return {"claimed": False, "reason_code": "DISPATCH_RECORD_WRITE_FAILED"}
    finally:
        os.close(fd)
    return {
        "claimed": True,
        "reason_code": "DISPATCH_CLAIMED_ONE_SHOT",
        "operation_id": operation_id,
        "target_state": target,
    }
