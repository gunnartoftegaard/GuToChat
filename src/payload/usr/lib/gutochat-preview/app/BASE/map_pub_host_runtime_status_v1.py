"""Safe runtime-status bridge for the host-side MAP-PUB proxy.

This module intentionally exposes only non-secret process/arm readiness state via
an owner-only file under /run.  It never reads broker credentials or the arm
credential content.  The reader treats stale, malformed, wrong-owner, wrong-mode
or dead-process status as unverified/fail-closed.
"""
from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Callable

SCHEMA = "gutochat.map_pub.host_runtime_status.v1"
DEFAULT_STATUS_PATH = Path("/run/gutochat-map-pub/map-pub-host-runtime-status-v1.json")
DEFAULT_HEARTBEAT_SECONDS = 2.0
DEFAULT_MAX_AGE_SECONDS = 6.0
EXPECTED_CMDLINE_MARKER = "app.map_pub_proxy_runtime_v7r3"


class HostRuntimeStatusPublisher:
    def __init__(
        self,
        path: str | Path = DEFAULT_STATUS_PATH,
        *,
        heartbeat_seconds: float = DEFAULT_HEARTBEAT_SECONDS,
        wall_clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        pid: int | None = None,
    ) -> None:
        if heartbeat_seconds <= 0:
            raise ValueError("STATUS_HEARTBEAT_MUST_BE_POSITIVE")
        self.path = Path(path)
        self.heartbeat_seconds = float(heartbeat_seconds)
        self._wall_clock = wall_clock
        self._monotonic = monotonic
        self.pid = int(os.getpid() if pid is None else pid)
        self._last_write_mono = float("-inf")
        self._last_state: tuple[bool, bool] | None = None

    def _write(self, armed: bool, revoked_latched: bool) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.tmp-{self.pid}")
        payload = {
            "schema": SCHEMA,
            "pid": self.pid,
            "armed": bool(armed),
            "revoked_latched": bool(revoked_latched),
            "updated_epoch": float(self._wall_clock()),
        }
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(tmp), flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    def update_from_interlock(self, interlock: Any, poll_result: Any = None, *, force: bool = False) -> dict[str, Any]:
        revoked = bool(getattr(interlock, "revoked_latched", True))
        if poll_result is None:
            if self._last_state is None:
                armed = not revoked
            else:
                armed = bool(self._last_state[0])
        else:
            armed = bool(poll_result)
        if revoked:
            armed = False

        state = (armed, revoked)
        now_mono = self._monotonic()
        due = now_mono - self._last_write_mono >= self.heartbeat_seconds
        if force or state != self._last_state or due:
            self._write(armed, revoked)
            self._last_write_mono = now_mono
            self._last_state = state
        return {"armed": armed, "revoked_latched": revoked}


def _unverified(reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "verified": False,
        "armed": None,
        "revoked_latched": None,
        "pid": None,
        "age_seconds": None,
        "reason_code": reason,
    }


def read_host_runtime_status(
    path: str | Path = DEFAULT_STATUS_PATH,
    *,
    max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
    wall_clock: Callable[[], float] = time.time,
    expected_uid: int | None = None,
    process_probe: Callable[[int], None] | None = None,
    cmdline_reader: Callable[[int], str] | None = None,
    expected_cmdline_marker: str = EXPECTED_CMDLINE_MARKER,
) -> dict[str, Any]:
    """Read and validate the non-secret host runtime status file.

    ``process_probe`` follows ``os.kill(pid, 0)`` semantics and may be injected
    in tests.  A verified status guarantees only process-local arm readiness;
    transport ownership/path readiness is checked separately by meshbridge.
    """
    p = Path(path)
    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    if process_probe is None:
        process_probe = lambda pid: os.kill(pid, 0)
    if cmdline_reader is None:
        def cmdline_reader(pid: int) -> str:
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
            return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")
    try:
        st = p.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return _unverified("HOST_RUNTIME_STATUS_NOT_REGULAR")
        if st.st_uid != uid:
            return _unverified("HOST_RUNTIME_STATUS_OWNER_MISMATCH")
        if stat.S_IMODE(st.st_mode) != 0o600:
            return _unverified("HOST_RUNTIME_STATUS_MODE_MISMATCH")
        raw = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
            return _unverified("HOST_RUNTIME_STATUS_SCHEMA_INVALID")
        pid = int(raw.get("pid", 0))
        armed = raw.get("armed")
        revoked = raw.get("revoked_latched")
        updated = float(raw.get("updated_epoch", 0.0))
        if pid <= 0 or not isinstance(armed, bool) or not isinstance(revoked, bool):
            return _unverified("HOST_RUNTIME_STATUS_FIELDS_INVALID")
        if armed and revoked:
            return _unverified("HOST_RUNTIME_STATUS_INCONSISTENT")
        age = float(wall_clock()) - updated
        if age < -2.0 or age > float(max_age_seconds):
            return _unverified("HOST_RUNTIME_STATUS_STALE")
        process_probe(pid)
        cmdline = str(cmdline_reader(pid))
        if expected_cmdline_marker and expected_cmdline_marker not in cmdline:
            return _unverified("HOST_RUNTIME_STATUS_PROCESS_MISMATCH")
        return {
            "schema": SCHEMA,
            "verified": True,
            "armed": armed,
            "revoked_latched": revoked,
            "pid": pid,
            "age_seconds": max(0.0, age),
            "reason_code": "HOST_RUNTIME_STATUS_VERIFIED",
        }
    except FileNotFoundError:
        return _unverified("HOST_RUNTIME_STATUS_MISSING")
    except ProcessLookupError:
        return _unverified("HOST_RUNTIME_STATUS_PROCESS_DEAD")
    except PermissionError:
        return _unverified("HOST_RUNTIME_STATUS_PERMISSION_DENIED")
    except Exception:
        return _unverified("HOST_RUNTIME_STATUS_READ_FAILED")
