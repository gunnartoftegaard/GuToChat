#!/usr/bin/env python3
"""Bounded retry helpers for transient SQLite lock contention."""
from __future__ import annotations

import sqlite3
import time
from typing import Callable, TypeVar, Any

T = TypeVar("T")
_LOCK_MARKERS = (
    "database is locked",
    "database table is locked",
    "database schema is locked",
)


def is_sqlite_lock_error(exc: BaseException) -> bool:
    """Return True only for transient SQLite lock-contention errors."""
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    text = str(exc).strip().lower()
    return any(marker in text for marker in _LOCK_MARKERS)


def sqlite_locked_retry(
    operation: Callable[[], T],
    *,
    label: str,
    logger: Any = None,
    attempts: int = 6,
    initial_delay: float = 0.25,
    max_delay: float = 2.0,
) -> T:
    """Retry one startup SQLite operation only when the DB is transiently locked.

    Existing SQLite connections use a 5 s busy timeout.  Six attempts therefore
    provide a bounded additional startup tolerance of roughly 36 s including
    backoff, while all non-lock errors remain immediately fatal.
    """
    count = max(1, int(attempts))
    delay = max(0.0, float(initial_delay))
    ceiling = max(delay, float(max_delay))

    for attempt in range(1, count + 1):
        try:
            return operation()
        except sqlite3.OperationalError as exc:
            if not is_sqlite_lock_error(exc) or attempt >= count:
                raise
            wait = min(ceiling, delay)
            if logger is not None:
                logger.warning(
                    "SQLite låst under %s; nytt forsøk %s/%s om %.2f s",
                    label,
                    attempt + 1,
                    count,
                    wait,
                )
            if wait > 0:
                time.sleep(wait)
            delay = min(ceiling, max(initial_delay, delay * 2 if delay else initial_delay))
    raise RuntimeError("unreachable")
