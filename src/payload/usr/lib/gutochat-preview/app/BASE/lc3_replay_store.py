#!/usr/bin/env python3
"""Durable replay protection for authenticated LC3 control frames."""
from __future__ import annotations

from contextlib import contextmanager

import sqlite3
import math
import time

from sqlite_resilience import sqlite_locked_retry
from pathlib import Path


class LC3ReplayStore:
    """Persist accepted LC3 authentication nonces in the product database.

    Entries live only as long as a timestamped authenticated frame could still
    pass the configured freshness window.  The insert is atomic, so concurrent
    Base/Mobile consumers sharing one SQLite database cannot accept the same
    ``(key_id, nonce)`` twice.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=10)
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA busy_timeout=5000")
            return con
        except BaseException:
            con.close()
            raise

    @contextmanager
    def _connection(self):
        """OFFLINE REVIEW: finish transaction and close on every exit."""
        con = self._connect()
        try:
            with con:
                yield con
        finally:
            con.close()

    def _init_db(self) -> None:
        with self._connection() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS lc3_auth_replay (
                    key_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    authenticated_epoch INTEGER NOT NULL,
                    expires_epoch INTEGER NOT NULL,
                    PRIMARY KEY(key_id, nonce)
                )
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_lc3_auth_replay_expiry "
                "ON lc3_auth_replay(expires_epoch)"
            )

    def check_and_remember(
        self,
        key_id: str,
        nonce: str,
        authenticated_epoch: int,
        *,
        current_epoch: int,
        max_skew_seconds: int,
    ) -> bool:
        """Atomically accept a fresh nonce once, returning ``False`` on replay."""
        started = time.monotonic()
        skew = max(30, int(max_skew_seconds))
        expires = int(authenticated_epoch) + skew

        def remember() -> bool:
            with self._connection() as con:
                con.execute("BEGIN IMMEDIATE")
                # Waiting for a writer must not extend the authenticated window.
                effective_current = int(current_epoch) + math.ceil(
                    max(0.0, time.monotonic() - started)
                )
                if abs(effective_current - int(authenticated_epoch)) > skew:
                    raise ValueError("LC3-auth frame expired while waiting for storage")
                con.execute(
                    "DELETE FROM lc3_auth_replay WHERE expires_epoch < ?",
                    (effective_current,),
                )
                row = con.execute(
                    "SELECT 1 FROM lc3_auth_replay WHERE key_id = ? AND nonce = ?",
                    (str(key_id), str(nonce)),
                ).fetchone()
                if row is not None:
                    return False
                con.execute(
                    """
                    INSERT INTO lc3_auth_replay(
                        key_id, nonce, authenticated_epoch, expires_epoch
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (str(key_id), str(nonce), int(authenticated_epoch), expires),
                )
            return True

        return sqlite_locked_retry(
            remember, label="LC3 nonce transaction", attempts=3
        )
