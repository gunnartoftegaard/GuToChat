#!/usr/bin/env python3
"""Persistent node and gateway cache shared by the GUI and bridge services."""
from __future__ import annotations

from contextlib import contextmanager

import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def node_num_from_id(node_id: str) -> int:
    value = node_id.strip().lower()
    if value.startswith("!"):
        value = value[1:]
    if len(value) != 8 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("Node-ID må være ! etterfulgt av åtte heksadesimale tegn")
    return int(value, 16)


class NodeCatalog:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=10)
        try:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA busy_timeout=5000")
            return con
        except BaseException:
            con.close()
            raise

    @contextmanager
    def _connection(self):
        """Transaction context that always closes the SQLite connection.

        ``sqlite3.Connection`` as a context manager commits or rolls back the
        transaction, but does not close the connection.  Bridge/status paths
        are long-lived processes, so relying on cyclic/GC cleanup can retain
        database and WAL file descriptors for an unbounded interval.
        """
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
                CREATE TABLE IF NOT EXISTS node_catalog (
                    network TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    num INTEGER NOT NULL,
                    long_name TEXT NOT NULL DEFAULT '',
                    short_name TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_heard INTEGER,
                    last_updated TEXT NOT NULL,
                    snr REAL,
                    source TEXT NOT NULL DEFAULT '',
                    manual INTEGER NOT NULL DEFAULT 0,
                    revision INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(network, node_id)
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS node_catalog_state (
                    network TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL DEFAULT 0,
                    remote_revision INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS gateway_cache (
                    route TEXT PRIMARY KEY,
                    status_json TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_node_catalog_revision "
                "ON node_catalog(network, revision)"
            )

    @staticmethod
    def _next_revision(con: sqlite3.Connection, network: str) -> int:
        con.execute(
            "INSERT OR IGNORE INTO node_catalog_state(network, revision, remote_revision) "
            "VALUES (?, 0, 0)",
            (network,),
        )
        con.execute(
            "UPDATE node_catalog_state SET revision = revision + 1 WHERE network = ?",
            (network,),
        )
        row = con.execute(
            "SELECT revision FROM node_catalog_state WHERE network = ?", (network,)
        ).fetchone()
        return int(row[0])

    def _upsert_on_connection(
        self,
        con: sqlite3.Connection,
        network: str,
        node: dict[str, Any],
        *,
        source: str,
        manual: bool = False,
        external_revision: int | None = None,
    ) -> bool:
        """Upsert one node using an already-open transaction.

        Keeping the transaction owned by the caller lets ``upsert_many`` apply
        one local Meshtastic snapshot with a single SQLite writer acquisition
        instead of opening and committing one connection per node.
        """
        node_id = str(node.get("id") or "").strip().lower()
        num_value = node.get("num")
        if not node_id and num_value is not None:
            node_id = f"!{int(num_value):08x}"
        if not node_id:
            raise ValueError("Noden mangler node-ID")
        if not node_id.startswith("!"):
            node_id = "!" + node_id
        num = int(num_value) if num_value is not None else node_num_from_id(node_id)
        long_name = str(node.get("long_name") or "")
        short_name = str(node.get("short_name") or "")
        last_heard_raw = node.get("last_heard")
        last_heard = int(last_heard_raw) if last_heard_raw not in (None, "") else None
        snr_raw = node.get("snr")
        snr = float(snr_raw) if snr_raw not in (None, "") else None
        updated = str(node.get("last_updated") or now_iso())

        existing = con.execute(
            "SELECT * FROM node_catalog WHERE network = ? AND node_id = ?",
            (network, node_id),
        ).fetchone()
        # Once a node has been entered manually, keep that fact when live
        # radio metadata later refreshes the same node. Comparing against the
        # preserved value prevents a false new delta revision on every poll.
        preserved_manual = max(
            int(existing["manual"]) if existing is not None else 0,
            1 if manual else 0,
        )
        meaningful = (
            num,
            long_name,
            short_name,
            last_heard,
            snr,
            source,
            preserved_manual,
        )
        if existing is not None:
            old = (
                int(existing["num"]),
                str(existing["long_name"]),
                str(existing["short_name"]),
                existing["last_heard"],
                existing["snr"],
                str(existing["source"]),
                int(existing["manual"]),
            )
            if old == meaningful:
                # The bridge and GUI share this catalog.  A duplicate GUI
                # observation may carry the exact timestamp already committed by
                # the bridge; avoid turning that readback into another writer.
                if str(existing["last_updated"]) != updated:
                    con.execute(
                        "UPDATE node_catalog SET last_updated = ? "
                        "WHERE network = ? AND node_id = ?",
                        (updated, network, node_id),
                    )
                return False

        revision = (
            max(0, int(external_revision))
            if external_revision is not None and int(external_revision) > 0
            else self._next_revision(con, network)
        )
        first_seen = str(existing["first_seen"]) if existing is not None else updated
        con.execute(
            """
            INSERT INTO node_catalog(
                network, node_id, num, long_name, short_name, first_seen,
                last_heard, last_updated, snr, source, manual, revision
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(network, node_id) DO UPDATE SET
                num = excluded.num,
                long_name = excluded.long_name,
                short_name = excluded.short_name,
                last_heard = excluded.last_heard,
                last_updated = excluded.last_updated,
                snr = excluded.snr,
                source = excluded.source,
                manual = MAX(node_catalog.manual, excluded.manual),
                revision = excluded.revision
            """,
            (
                network,
                node_id,
                num,
                long_name,
                short_name,
                first_seen,
                last_heard,
                updated,
                snr,
                source,
                1 if manual else 0,
                revision,
            ),
        )
        # A received remote revision is a cursor, not our local change counter.
        if external_revision is not None and int(external_revision) > 0:
            con.execute(
                "INSERT OR IGNORE INTO node_catalog_state(network, revision, remote_revision) "
                "VALUES (?, 0, 0)",
                (network,),
            )
        return True

    def upsert(
        self,
        network: str,
        node: dict[str, Any],
        *,
        source: str,
        manual: bool = False,
        external_revision: int | None = None,
    ) -> bool:
        with self._connection() as con:
            return self._upsert_on_connection(
                con,
                network,
                node,
                source=source,
                manual=manual,
                external_revision=external_revision,
            )

    def upsert_many(
        self, network: str, nodes: Iterable[dict[str, Any]], *, source: str
    ) -> int:
        changed = 0
        with self._connection() as con:
            for node in nodes:
                if self._upsert_on_connection(con, network, node, source=source):
                    changed += 1
        return changed

    def add_manual(self, network: str, node_id: str, name: str = "") -> dict[str, Any]:
        normalized = node_id.strip().lower()
        if not normalized.startswith("!"):
            normalized = "!" + normalized
        num = node_num_from_id(normalized)
        node = {
            "id": normalized,
            "num": num,
            "long_name": name.strip(),
            "short_name": "",
            "last_updated": now_iso(),
        }
        self.upsert(network, node, source="manual", manual=True)
        return node

    def list_nodes(self, network: str, since_revision: int = 0) -> list[dict[str, Any]]:
        with self._connection() as con:
            rows = con.execute(
                """
                SELECT * FROM node_catalog
                 WHERE network = ? AND revision > ?
                 ORDER BY revision ASC, COALESCE(long_name, ''), node_id
                """,
                (network, max(0, int(since_revision))),
            ).fetchall()
        return [dict(row) for row in rows]

    def count(self, network: str) -> int:
        with self._connection() as con:
            row = con.execute(
                "SELECT COUNT(*) FROM node_catalog WHERE network = ?", (network,)
            ).fetchone()
        return int(row[0])

    def current_revision(self, network: str) -> int:
        with self._connection() as con:
            row = con.execute(
                "SELECT revision FROM node_catalog_state WHERE network = ?", (network,)
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def remote_revision(self, network: str) -> int:
        with self._connection() as con:
            row = con.execute(
                "SELECT remote_revision FROM node_catalog_state WHERE network = ?",
                (network,),
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def set_remote_revision(self, network: str, revision: int) -> None:
        with self._connection() as con:
            con.execute(
                """
                INSERT INTO node_catalog_state(network, revision, remote_revision)
                VALUES (?, 0, ?)
                ON CONFLICT(network) DO UPDATE SET remote_revision = excluded.remote_revision
                """,
                (network, max(0, int(revision))),
            )

    def save_gateway_status(self, route: str, status: dict[str, Any]) -> None:
        payload = dict(status)
        last_seen = str(payload.get("last_seen") or now_iso())
        payload["last_seen"] = last_seen
        with self._connection() as con:
            con.execute(
                """
                INSERT INTO gateway_cache(route, status_json, last_seen)
                VALUES (?, ?, ?)
                ON CONFLICT(route) DO UPDATE SET
                    status_json = excluded.status_json,
                    last_seen = excluded.last_seen
                """,
                (route, json.dumps(payload, ensure_ascii=False), last_seen),
            )

    def load_gateway_status(self, route: str) -> dict[str, Any]:
        with self._connection() as con:
            row = con.execute(
                "SELECT status_json, last_seen FROM gateway_cache WHERE route = ?",
                (route,),
            ).fetchone()
        if row is None:
            return {}
        try:
            value = json.loads(str(row["status_json"]))
        except json.JSONDecodeError:
            value = {}
        value.setdefault("last_seen", str(row["last_seen"]))
        value["cached"] = True
        return value

    @staticmethod
    def is_stale(node: dict[str, Any], stale_hours: float) -> bool:
        if bool(node.get("manual")) and not node.get("last_heard"):
            return True
        cutoff = time.time() - max(0.0, float(stale_hours)) * 3600
        last_heard = node.get("last_heard")
        if last_heard not in (None, ""):
            try:
                return float(last_heard) < cutoff
            except (TypeError, ValueError):
                pass
        updated = str(node.get("last_updated") or "")
        try:
            return datetime.fromisoformat(updated).timestamp() < cutoff
        except Exception:
            return True
