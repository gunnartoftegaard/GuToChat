#!/usr/bin/env python3
"""Host-global fail-closed lease for every APRS-IS uplink sender path.

The lease serializes ownership across persistent, isolated and one-shot public
senders.  It performs no network I/O and carries no APRS payload or credential.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
from typing import Iterator

WORKER_LOCK = Path('/var/lib/gutochat-aprs-igate/uplink-worker.lock')


class WorkerLeaseHeld(RuntimeError):
    pass


class UplinkWorkerLease:
    def __init__(self, path: str | Path = WORKER_LOCK) -> None:
        self.path = Path(path)
        self.fd: int | None = None

    def acquire(self) -> None:
        if self.fd is not None:
            raise RuntimeError('UPLINK_WORKER_LEASE_ALREADY_ACQUIRED')
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise WorkerLeaseHeld('UPLINK_WORKER_LEASE_HELD') from exc
        except Exception:
            os.close(fd)
            raise
        self.fd = fd

    def close(self) -> None:
        fd, self.fd = self.fd, None
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> 'UplinkWorkerLease':
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@contextmanager
def worker_lease(path: str | Path = WORKER_LOCK) -> Iterator[UplinkWorkerLease]:
    lease = UplinkWorkerLease(path)
    lease.acquire()
    try:
        yield lease
    finally:
        lease.close()
