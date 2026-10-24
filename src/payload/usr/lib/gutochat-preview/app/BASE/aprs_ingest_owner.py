#!/usr/bin/env python3
"""Cross-process APRS ingest ownership guard.

The lock is deliberately separate from SQLite locking.  It prevents two
GuToChat processes from owning simultaneous APRS-IS sessions while allowing
one writer and any number of read-only map consumers to share aprs.db.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import time
from typing import IO

try:  # Target platform is Linux; absence must fail closed.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on unsupported OS.
    fcntl = None  # type: ignore[assignment]


class AprsIngestOwnershipError(RuntimeError):
    """Raised when another process already owns APRS live ingest."""


def default_ingest_lock_path(database_path: Path) -> Path:
    db = Path(database_path).expanduser().resolve()
    return db.with_name(db.name + ".ingest.lock")


@dataclass(frozen=True)
class AprsIngestOwnerSnapshot:
    active: bool
    role: str


class AprsIngestOwner:
    """Hold an advisory exclusive lock for one APRS ingest owner."""

    def __init__(self, lock_path: Path, *, role: str) -> None:
        path = Path(lock_path).expanduser()
        if not path.is_absolute():
            raise ValueError("APRS ingest lock path must be absolute")
        clean_role = str(role).strip().lower()
        if clean_role not in {"gui", "headless", "test"}:
            raise ValueError("Invalid APRS ingest owner role")
        self.lock_path = Path(os.path.abspath(path))
        self.role = clean_role
        self._handle: IO[str] | None = None

    @property
    def active(self) -> bool:
        return self._handle is not None

    def snapshot(self) -> AprsIngestOwnerSnapshot:
        return AprsIngestOwnerSnapshot(active=self.active, role=self.role)

    def acquire(self) -> None:
        if self._handle is not None:
            raise RuntimeError("APRS ingest ownership is already held by this runtime")
        if fcntl is None:
            raise AprsIngestOwnershipError("APRS ingest ownership requires POSIX flock")

        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.lock_path, flags, 0o600)
        try:
            mode = os.fstat(fd).st_mode
            if not stat.S_ISREG(mode):
                raise AprsIngestOwnershipError("APRS ingest lock is not a regular file")
            os.fchmod(fd, 0o600)
            handle = os.fdopen(fd, "r+", encoding="utf-8", closefd=True)
            fd = -1
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                handle.close()
                raise AprsIngestOwnershipError("APRS ingest already has an active owner") from exc

            metadata = {
                "schema_version": 1,
                "role": self.role,
                "pid": os.getpid(),
                "acquired_epoch": time.time(),
            }
            handle.seek(0)
            handle.truncate(0)
            json.dump(metadata, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            self._handle = handle
        finally:
            if fd >= 0:
                os.close(fd)

    def release(self) -> None:
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    def __enter__(self) -> "AprsIngestOwner":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()
