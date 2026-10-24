#!/usr/bin/env python3
"""SQLite message history and durable Waveshare outbox."""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


class MessageStore:
    """SQLite message history plus a durable Waveshare outbox."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Yield one transactional SQLite connection and always close it.

        ``sqlite3.Connection`` as a context manager commits/rolls back but does
        not itself guarantee an immediate close.  GuToChat performs frequent
        short-lived history/API reads, so deterministic close is required to
        prevent database/WAL descriptors from accumulating until cyclic GC.
        """
        con = sqlite3.connect(self.db_path, timeout=10)
        try:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA busy_timeout=5000")
            with con:
                yield con
        finally:
            con.close()

    @staticmethod
    def _columns(con: sqlite3.Connection, table: str) -> set[str]:
        return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table})")}

    def _startup_repair_needs(self) -> dict[str, bool]:
        """Probe legacy data without reserving the database's writer lock.

        Each probe can scan the full history. Keep these reads outside the
        schema transaction so concurrent services can continue writing.
        A repair selected here is checked again inside the write transaction.
        Missing tables/columns are handled after schema creation below.
        """
        needed = {"updated_at": True, "source_label": True, "destination_label": True}
        with self._connect() as con:
            columns = self._columns(con, "messages")
            if "updated_at" in columns:
                needed["updated_at"] = con.execute(
                    "SELECT 1 FROM messages WHERE updated_at IS NULL LIMIT 1"
                ).fetchone() is not None
            for field, number in (("source_label", "source"), ("destination_label", "destination")):
                if {"network", field, number}.issubset(columns):
                    needed[field] = con.execute(
                        f"SELECT 1 FROM messages WHERE COALESCE(network, '') LIKE 'Meshtastic%' "
                        f"AND {number} BETWEEN 0 AND 4294967294 "
                        f"AND {field} IN (CAST({number} AS TEXT), '!' || CAST({number} AS TEXT)) LIMIT 1"
                    ).fetchone() is not None
        return needed

    def _init_db(self) -> None:
        repairs = self._startup_repair_needs()
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_uid TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    source INTEGER NOT NULL,
                    destination INTEGER NOT NULL,
                    broadcast INTEGER NOT NULL DEFAULT 0,
                    text TEXT NOT NULL,
                    packet_rssi INTEGER,
                    status TEXT NOT NULL,
                    raw_hex TEXT
                )
                """
            )
            columns = self._columns(con, "messages")
            additions = {
                "ack_rssi": "INTEGER",
                "attempts": "INTEGER NOT NULL DEFAULT 1",
                "updated_at": "TEXT",
                "network": "TEXT NOT NULL DEFAULT 'Waveshare'",
                "source_label": "TEXT",
                "destination_label": "TEXT",
                "snr": "REAL",
                "channel": "INTEGER",
                "gateway_request_id": "TEXT NOT NULL DEFAULT ''",
                "sync_origin": "TEXT NOT NULL DEFAULT ''",
                "remote_message_id": "INTEGER",
            }
            for name, definition in additions.items():
                if name not in columns:
                    con.execute(f"ALTER TABLE messages ADD COLUMN {name} {definition}")
            if repairs["updated_at"] and con.execute(
                "SELECT 1 FROM messages WHERE updated_at IS NULL LIMIT 1"
            ).fetchone() is not None:
                con.execute(
                    "UPDATE messages SET updated_at = timestamp WHERE updated_at IS NULL"
                )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_uid ON messages(message_uid)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_gateway_request "
                "ON messages(gateway_request_id)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_network_id "
                "ON messages(network, id)"
            )
            # Older Meshtastic/Python combinations could expose toId/fromId
            # as ! followed by the decimal node number.  Avoid taking a long
            # write transaction on every process startup when there is nothing
            # left to repair: probe read-only first, then update only if needed.
            source_label_repair_where = """
                COALESCE(network, '') LIKE 'Meshtastic%'
                AND source BETWEEN 0 AND 4294967294
                AND source_label IN (CAST(source AS TEXT), '!' || CAST(source AS TEXT))
            """
            if repairs["source_label"] and con.execute(
                f"SELECT 1 FROM messages WHERE {source_label_repair_where} LIMIT 1"
            ).fetchone() is not None:
                con.execute(
                    f"""
                    UPDATE messages
                       SET source_label = printf('!%08x', source)
                     WHERE {source_label_repair_where}
                    """
                )

            destination_label_repair_where = """
                COALESCE(network, '') LIKE 'Meshtastic%'
                AND destination BETWEEN 0 AND 4294967294
                AND destination_label IN (
                    CAST(destination AS TEXT),
                    '!' || CAST(destination AS TEXT)
                )
            """
            if repairs["destination_label"] and con.execute(
                f"SELECT 1 FROM messages WHERE {destination_label_repair_where} LIMIT 1"
            ).fetchone() is not None:
                con.execute(
                    f"""
                    UPDATE messages
                       SET destination_label = printf('!%08x', destination)
                     WHERE {destination_label_repair_where}
                    """
                )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_packets (
                    message_uid TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    first_seen_epoch REAL,
                    source INTEGER NOT NULL
                )
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_seen_packets_retention_epoch "
                "ON seen_packets(first_seen_epoch, message_uid)"
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS outbox (
                    message_uid TEXT PRIMARY KEY,
                    destination INTEGER NOT NULL,
                    text TEXT NOT NULL,
                    state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_epoch REAL NOT NULL,
                    expires_epoch REAL NOT NULL,
                    last_attempt_epoch REAL,
                    last_error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            outbox_columns = self._columns(con, "outbox")
            outbox_additions = {
                "traffic_class": "TEXT NOT NULL DEFAULT 'user'",
                "control_command": "TEXT NOT NULL DEFAULT ''",
                "control_route": "TEXT NOT NULL DEFAULT ''",
                "control_request_id": "TEXT NOT NULL DEFAULT ''",
                "control_group": "TEXT NOT NULL DEFAULT ''",
                "max_attempts": "INTEGER",
                "priority": "INTEGER NOT NULL DEFAULT 100",
                "paused_at_epoch": "REAL",
            }
            for name, definition in outbox_additions.items():
                if name not in outbox_columns:
                    con.execute(f"ALTER TABLE outbox ADD COLUMN {name} {definition}")
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_outbox_due "
                "ON outbox(state, next_attempt_epoch)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_outbox_control_group "
                "ON outbox(destination, control_group, control_request_id)"
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS queue_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    queue_kind TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT '',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    detail TEXT NOT NULL DEFAULT '',
                    occurred_at TEXT NOT NULL,
                    occurred_epoch REAL NOT NULL
                )
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_queue_events_item "
                "ON queue_events(queue_kind, item_id, sequence)"
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS message_sync_state (
                    route TEXT PRIMARY KEY,
                    remote_sequence INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _append_queue_event(
        con: sqlite3.Connection,
        queue_kind: str,
        item_id: str,
        event_type: str,
        *,
        state: str = "",
        attempts: int = 0,
        detail: str = "",
    ) -> None:
        """Append privacy-safe queue history without storing message text."""
        con.execute(
            """
            INSERT INTO queue_events(
                queue_kind, item_id, event_type, state, attempts, detail,
                occurred_at, occurred_epoch
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(queue_kind),
                str(item_id),
                str(event_type),
                str(state),
                max(0, int(attempts)),
                str(detail or "")[:500],
                now_iso(),
                time.time(),
            ),
        )

    def queue_history(self, message_uid: str, limit: int = 50) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 200))
        with self._connect() as con:
            rows = con.execute(
                """
                SELECT sequence, event_type, state, attempts, detail,
                       occurred_at, occurred_epoch
                  FROM queue_events
                 WHERE queue_kind = 'waveshare' AND item_id = ?
                 ORDER BY sequence DESC
                 LIMIT ?
                """,
                (str(message_uid), safe_limit),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    @staticmethod
    def _mark_discarded(
        con: sqlite3.Connection, message_uids: list[str], status: str
    ) -> int:
        if not message_uids:
            return 0
        stamp = now_iso()
        placeholders = ",".join("?" for _ in message_uids)
        con.execute(
            f"UPDATE messages SET status = ?, updated_at = ? "
            f"WHERE message_uid IN ({placeholders}) AND direction = 'sent'",
            (status, stamp, *message_uids),
        )
        con.execute(
            f"DELETE FROM outbox WHERE message_uid IN ({placeholders})",
            tuple(message_uids),
        )
        for message_uid in message_uids:
            MessageStore._append_queue_event(
                con,
                "waveshare",
                message_uid,
                "discarded",
                state="discarded",
                detail=status,
            )
        return len(message_uids)

    def _backfill_control_policy(self, con: sqlite3.Connection) -> None:
        """Classify rows created by beta1/beta1a before metadata existed."""
        from protocol import control_transport_policy

        rows = con.execute(
            "SELECT message_uid, destination, text, expires_epoch, traffic_class "
            "FROM outbox"
        ).fetchall()
        current = time.time()
        for row in rows:
            if str(row["traffic_class"] or "user") != "user":
                continue
            policy = control_transport_policy(
                str(row["text"]), int(row["destination"])
            )
            if not policy:
                continue
            expires = min(
                float(row["expires_epoch"]),
                current + float(policy.get("ttl_seconds", 180.0)),
            )
            con.execute(
                """
                UPDATE outbox SET
                    traffic_class = ?, control_command = ?, control_route = ?,
                    control_request_id = ?, control_group = ?, max_attempts = ?,
                    expires_epoch = ?
                 WHERE message_uid = ?
                """,
                (
                    str(policy.get("traffic_class", "sync")),
                    str(policy.get("control_command", "")),
                    str(policy.get("control_route", "")),
                    str(policy.get("control_request_id", "")),
                    str(policy.get("control_group", "")),
                    int(policy.get("max_attempts", 3)),
                    expires,
                    str(row["message_uid"]),
                ),
            )

    def cleanup_stale_control_outbox(self) -> int:
        """Discard exhausted and superseded transient synchronization rows."""
        removed = 0
        with self._connect() as con:
            self._backfill_control_policy(con)
            exhausted = [
                str(row[0])
                for row in con.execute(
                    """
                    SELECT message_uid FROM outbox
                     WHERE traffic_class = 'sync'
                       AND max_attempts IS NOT NULL
                       AND attempts >= max_attempts
                    """
                ).fetchall()
            ]
            removed += self._mark_discarded(
                con, exhausted, "Foreldet kontrollmelding fjernet ved oppgradering"
            )

            rows = con.execute(
                """
                SELECT rowid, message_uid, destination, control_group,
                       control_request_id
                  FROM outbox
                 WHERE traffic_class = 'sync' AND control_group <> ''
                 ORDER BY rowid
                """
            ).fetchall()
            groups: dict[tuple[int, str], dict[str, list[tuple[int, str]]]] = {}
            for row in rows:
                key = (int(row["destination"]), str(row["control_group"]))
                request = str(row["control_request_id"])
                groups.setdefault(key, {}).setdefault(request, []).append(
                    (int(row["rowid"]), str(row["message_uid"]))
                )
            superseded: list[str] = []
            for requests in groups.values():
                if len(requests) <= 1:
                    continue
                newest_request = max(
                    requests, key=lambda request: max(item[0] for item in requests[request])
                )
                for request, items in requests.items():
                    if request != newest_request:
                        superseded.extend(uid for _, uid in items)
            removed += self._mark_discarded(
                con, superseded, "Erstattet av nyere kontrollsynkronisering"
            )
        return removed

    def integrity_check(self) -> str:
        """Run SQLite's non-destructive integrity check."""
        try:
            with self._connect() as con:
                rows = [str(row[0]) for row in con.execute("PRAGMA integrity_check")]
            return "; ".join(rows[:10]) if rows else "ukjent"
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"

    def maintenance(
        self,
        *,
        seen_packet_days: float = 30.0,
        fragment_ttl_seconds: float = 900.0,
        include_integrity: bool = True,
    ) -> dict[str, Any]:
        """Perform bounded housekeeping without deleting user messages.

        Full ``PRAGMA integrity_check`` is intentionally optional.  Periodic
        production housekeeping must not rescan the entire live database every
        few minutes; explicit/manual diagnostic maintenance can still request
        the full check.
        """
        current = time.time()
        stamp = now_iso()
        removed_control = self.cleanup_stale_control_outbox()
        removed_expired = 0
        removed_seen = 0
        removed_fragments = 0
        with self._connect() as con:
            expired = con.execute(
                "SELECT message_uid, traffic_class FROM outbox "
                "WHERE state NOT IN ('paused', 'expired_hold') AND expires_epoch <= ?",
                (current,),
            ).fetchall()
            removed_expired = self._expire_rows(con, expired, stamp=stamp,
                                                detail="Utløpt under databasevedlikehold")

            cutoff_iso = datetime.fromtimestamp(
                current - max(1.0, float(seen_packet_days)) * 86400
            ).astimezone().isoformat(timespec="seconds")
            removed_seen = con.execute(
                "DELETE FROM seen_packets WHERE first_seen < ?",
                (cutoff_iso,),
            ).rowcount

            tables = {
                str(row[0])
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "control_fragments" in tables:
                removed_fragments = con.execute(
                    "DELETE FROM control_fragments WHERE created_epoch < ?",
                    (current - max(60.0, float(fragment_ttl_seconds)),),
                ).rowcount

        return {
            "integrity": self.integrity_check() if include_integrity else "not_run",
            "removed_control": int(removed_control),
            "removed_expired": int(removed_expired),
            "removed_seen_packets": int(removed_seen),
            "removed_fragments": int(removed_fragments),
            "completed_at": now_iso(),
        }

    def recover_outbox(self) -> int:
        """Make unfinished rows eligible after pruning stale sync traffic."""
        removed = self.cleanup_stale_control_outbox()
        if removed:
            # The caller logs the number resumed; cleanup is intentionally
            # reflected in the message status rather than counted as resumed.
            pass
        current = time.time()
        stamp = now_iso()
        with self._connect() as con:
            expired = con.execute(
                "SELECT message_uid, traffic_class FROM outbox "
                "WHERE state NOT IN ('paused', 'expired_hold') AND expires_epoch <= ?",
                (current,),
            ).fetchall()
            self._expire_rows(
                con, expired, stamp=stamp, detail="Utløpt ved tjenestestart"
            )

            # Preserve long-duration retry schedules across service restarts.
            # Only an unfinished ACK transaction needs to become immediately due.
            interrupted = con.execute(
                "SELECT message_uid, attempts FROM outbox WHERE state = 'waiting_ack'"
            ).fetchall()
            con.execute(
                """
                UPDATE outbox
                   SET state = 'queued', next_attempt_epoch = ?, updated_at = ?
                 WHERE state = 'waiting_ack'
                """,
                (current, stamp),
            )
            rows = con.execute(
                "SELECT message_uid, state, attempts FROM outbox "
                "WHERE state IN ('queued', 'retry_wait')"
            ).fetchall()
            interrupted_ids = {str(row["message_uid"]) for row in interrupted}
            for row in rows:
                con.execute(
                    """
                    UPDATE messages SET status = ?, updated_at = ?
                     WHERE message_uid = ? AND direction = 'sent'
                    """,
                    (
                        "Venter på forbindelse (gjenopptatt)"
                        if str(row["message_uid"]) in interrupted_ids
                        else (
                            "Venter på planlagt nytt forsøk"
                            if str(row["state"]) == "retry_wait"
                            else "Venter i utboks"
                        ),
                        stamp,
                        str(row["message_uid"]),
                    ),
                )
                self._append_queue_event(
                    con,
                    "waveshare",
                    str(row["message_uid"]),
                    "recovered",
                    state=str(row["state"]),
                    attempts=int(row["attempts"]),
                    detail=(
                        "Uferdig ACK-transaksjon gjenopptatt etter tjenesteomstart"
                        if str(row["message_uid"]) in interrupted_ids
                        else "Køtilstand bevart etter tjenesteomstart"
                    ),
                )
        return len(rows)

    def enqueue_outbox(
        self,
        *,
        message_uid: str,
        source: int,
        destination: int,
        text: str,
        ttl_hours: float,
        traffic_class: str = "user",
        control_command: str = "",
        control_route: str = "",
        control_request_id: str = "",
        control_group: str = "",
        max_attempts: int | None = None,
        ttl_seconds: float | None = None,
        replace_other_requests: bool = False,
        priority: int | None = None,
        max_pending: int | None = None,
    ) -> None:
        stamp = now_iso()
        current = time.time()
        if ttl_seconds is None:
            expires = current + max(0.1, float(ttl_hours)) * 3600
        else:
            expires = current + max(5.0, float(ttl_seconds))
        effective_priority = int(priority) if priority is not None else (
            20 if str(traffic_class) == "sync" else 100
        )
        effective_priority = max(0, min(effective_priority, 1000))
        with self._connect() as con:
            if replace_other_requests and control_group:
                rows = con.execute(
                    """
                    SELECT message_uid FROM outbox
                     WHERE destination = ? AND control_group = ?
                       AND control_request_id <> ?
                    """,
                    (destination, control_group, control_request_id),
                ).fetchall()
                self._mark_discarded(
                    con,
                    [str(row[0]) for row in rows],
                    "Erstattet av nyere kontrollsynkronisering",
                )
            if max_pending is not None:
                pending_count = int(
                    con.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
                )
                if pending_count >= max(1, int(max_pending)):
                    raise RuntimeError(
                        f"Utboksen er full ({pending_count}/{int(max_pending)} poster)"
                    )
            con.execute(
                """
                INSERT INTO messages(
                    message_uid, timestamp, direction, source, destination,
                    broadcast, text, packet_rssi, status, raw_hex,
                    ack_rssi, attempts, updated_at
                ) VALUES (?, ?, 'sent', ?, ?, ?, ?, NULL, ?, NULL, NULL, 0, ?)
                """,
                (
                    message_uid,
                    stamp,
                    source,
                    destination,
                    1 if destination == 65535 else 0,
                    text,
                    "Lagt i utboks",
                    stamp,
                ),
            )
            con.execute(
                """
                INSERT INTO outbox(
                    message_uid, destination, text, state, attempts,
                    next_attempt_epoch, expires_epoch, last_attempt_epoch,
                    last_error, created_at, updated_at, traffic_class,
                    control_command, control_route, control_request_id,
                    control_group, max_attempts, priority, paused_at_epoch
                ) VALUES (?, ?, ?, 'queued', 0, ?, ?, NULL, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    message_uid, destination, text, current, expires, stamp, stamp,
                    traffic_class, control_command, control_route,
                    control_request_id, control_group, max_attempts,
                    effective_priority,
                ),
            )
            self._append_queue_event(
                con,
                "waveshare",
                message_uid,
                "queued",
                state="queued",
                attempts=0,
                detail="Lagt i varig Waveshare-utboks",
            )

    @classmethod
    def _expire_rows(
        cls,
        con: sqlite3.Connection,
        rows: list[sqlite3.Row] | tuple[sqlite3.Row, ...] | Any,
        *,
        stamp: str,
        detail: str,
    ) -> int:
        """Expire transient traffic, but hold user messages for manual renewal."""
        removed = 0
        for row in rows:
            uid = str(row["message_uid"])
            traffic_class = str(row["traffic_class"] or "user")
            if traffic_class == "user":
                con.execute(
                    "UPDATE outbox SET state = 'expired_hold', last_error = ?, updated_at = ? "
                    "WHERE message_uid = ?",
                    ("levetid utløpt – beholdt for manuell forlengelse", stamp, uid),
                )
                con.execute(
                    "UPDATE messages SET status = 'Levetid utløpt – beholdt i utboks', "
                    "updated_at = ? WHERE message_uid = ? AND direction = 'sent'",
                    (stamp, uid),
                )
                cls._append_queue_event(
                    con,
                    "waveshare",
                    uid,
                    "expired_hold",
                    state="expired_hold",
                    detail=detail + "; brukermeldingen er beholdt",
                )
            else:
                con.execute(
                    "UPDATE messages SET status = 'Utløpt i utboks', updated_at = ? "
                    "WHERE message_uid = ? AND direction = 'sent'",
                    (stamp, uid),
                )
                cls._append_queue_event(
                    con,
                    "waveshare",
                    uid,
                    "expired",
                    state="expired",
                    detail=detail,
                )
                con.execute("DELETE FROM outbox WHERE message_uid = ?", (uid,))
                removed += 1
        return removed

    def _expire_due(self, con: sqlite3.Connection, current: float) -> None:
        stamp = now_iso()
        rows = con.execute(
            "SELECT message_uid, traffic_class FROM outbox "
            "WHERE state NOT IN ('paused', 'expired_hold') AND expires_epoch <= ?",
            (current,),
        ).fetchall()
        self._expire_rows(con, rows, stamp=stamp, detail="Utløpt før levering")

    def next_outbox_due(self) -> dict[str, Any] | None:
        current = time.time()
        with self._connect() as con:
            self._expire_due(con, current)
            exhausted = [
                str(item[0])
                for item in con.execute(
                    "SELECT message_uid FROM outbox "
                    "WHERE max_attempts IS NOT NULL AND attempts >= max_attempts"
                ).fetchall()
            ]
            self._mark_discarded(
                con, exhausted, "Kontrollmelding utløpt etter maksimalt antall forsøk"
            )
            row = con.execute(
                """
                SELECT * FROM outbox
                 WHERE state IN ('queued', 'retry_wait')
                   AND next_attempt_epoch <= ?
                 ORDER BY priority DESC, next_attempt_epoch ASC, created_at ASC
                 LIMIT 1
                """,
                (current,),
            ).fetchone()
        return dict(row) if row is not None else None

    def refresh_sync_group_expiry(
        self,
        message_uid: str,
        *,
        ttl_seconds: float,
        control_group_prefix: str = "",
    ) -> int:
        """Renew one active sync response group after proven wire activity.

        Sync TTL remains bounded, but is treated as an inactivity lease rather
        than an absolute age from the instant a multi-frame response was queued.
        A newer request still supersedes the older request through the existing
        control_group/control_request_id replacement contract.
        """
        current = time.time()
        renewed_until = current + max(5.0, float(ttl_seconds))
        stamp = now_iso()
        with self._connect() as con:
            row = con.execute(
                """
                SELECT destination, traffic_class, control_group, control_request_id
                  FROM outbox
                 WHERE message_uid = ?
                """,
                (message_uid,),
            ).fetchone()
            if row is None or str(row["traffic_class"]) != "sync":
                return 0
            group = str(row["control_group"] or "")
            request_id = str(row["control_request_id"] or "")
            if not group or not request_id:
                return 0
            if control_group_prefix and not group.startswith(control_group_prefix):
                return 0
            result = con.execute(
                """
                UPDATE outbox
                   SET expires_epoch = CASE
                           WHEN expires_epoch < ? THEN ? ELSE expires_epoch END,
                       updated_at = ?
                 WHERE destination = ?
                   AND traffic_class = 'sync'
                   AND control_group = ?
                   AND control_request_id = ?
                   AND state IN ('queued', 'retry_wait', 'waiting_ack')
                """,
                (
                    renewed_until, renewed_until, stamp,
                    int(row["destination"]), group, request_id,
                ),
            )
            return max(0, int(result.rowcount or 0))

    def mark_wire_sent(
        self,
        message_uid: str,
        *,
        attempts: int,
        raw_hex: str,
        waiting_ack: bool,
        status: str,
    ) -> None:
        stamp = now_iso()
        current = time.time()
        with self._connect() as con:
            con.execute(
                """
                UPDATE messages
                   SET status = ?, attempts = ?, raw_hex = ?, updated_at = ?
                 WHERE message_uid = ? AND direction = 'sent'
                """,
                (status, attempts, raw_hex, stamp, message_uid),
            )
            if waiting_ack:
                con.execute(
                    """
                    UPDATE outbox
                       SET state = 'waiting_ack', attempts = ?,
                           last_attempt_epoch = ?, updated_at = ?, last_error = ''
                     WHERE message_uid = ?
                    """,
                    (attempts, current, stamp, message_uid),
                )
                self._append_queue_event(
                    con,
                    "waveshare",
                    message_uid,
                    "waiting_ack",
                    state="waiting_ack",
                    attempts=attempts,
                    detail=status,
                )
            else:
                con.execute("DELETE FROM outbox WHERE message_uid = ?", (message_uid,))
                self._append_queue_event(
                    con,
                    "waveshare",
                    message_uid,
                    "sent",
                    state="sent",
                    attempts=attempts,
                    detail=status,
                )

    def schedule_retry(
        self,
        message_uid: str,
        *,
        attempts: int,
        delay_seconds: float,
        status: str,
        error: str = "",
    ) -> bool:
        stamp = now_iso()
        with self._connect() as con:
            row = con.execute(
                "SELECT max_attempts FROM outbox WHERE message_uid = ?",
                (message_uid,),
            ).fetchone()
            if row is None:
                return False
            max_attempts = row[0]
            if max_attempts is not None and int(attempts) >= int(max_attempts):
                self._mark_discarded(
                    con,
                    [message_uid],
                    "Kontrollmelding utløpt etter maksimalt antall forsøk",
                )
                return False
            con.execute(
                """
                UPDATE outbox
                   SET state = 'retry_wait', attempts = ?, next_attempt_epoch = ?,
                       last_error = ?, updated_at = ?
                 WHERE message_uid = ?
                """,
                (
                    attempts,
                    time.time() + max(0.0, float(delay_seconds)),
                    error[:500],
                    stamp,
                    message_uid,
                ),
            )
            con.execute(
                """
                UPDATE messages SET status = ?, attempts = ?, updated_at = ?
                 WHERE message_uid = ? AND direction = 'sent'
                """,
                (status, attempts, stamp, message_uid),
            )
            self._append_queue_event(
                con,
                "waveshare",
                message_uid,
                "retry_wait",
                state="retry_wait",
                attempts=attempts,
                detail=error or status,
            )
        return True

    def complete_outbox(
        self,
        message_uid: str,
        *,
        status: str,
        ack_rssi: int | None = None,
    ) -> bool:
        stamp = now_iso()
        with self._connect() as con:
            cur = con.execute(
                """
                UPDATE messages
                   SET status = ?, ack_rssi = COALESCE(?, ack_rssi), updated_at = ?
                 WHERE message_uid = ? AND direction = 'sent'
                """,
                (status, ack_rssi, stamp, message_uid),
            )
            con.execute("DELETE FROM outbox WHERE message_uid = ?", (message_uid,))
            if cur.rowcount:
                self._append_queue_event(
                    con,
                    "waveshare",
                    message_uid,
                    "completed",
                    state="completed",
                    detail=status,
                )
        return cur.rowcount > 0

    def cancel_outbox(self, message_uid: str) -> bool:
        stamp = now_iso()
        with self._connect() as con:
            cur = con.execute("DELETE FROM outbox WHERE message_uid = ?", (message_uid,))
            if cur.rowcount:
                con.execute(
                    "UPDATE messages SET status = 'Avbrutt av bruker', updated_at = ? "
                    "WHERE message_uid = ? AND direction = 'sent'",
                    (stamp, message_uid),
                )
                self._append_queue_event(
                    con,
                    "waveshare",
                    message_uid,
                    "cancelled",
                    state="cancelled",
                    detail="Avbrutt av bruker",
                )
        return cur.rowcount > 0

    def retry_now(self, message_uid: str) -> bool:
        stamp = now_iso()
        with self._connect() as con:
            cur = con.execute(
                """
                UPDATE outbox SET state = 'queued', next_attempt_epoch = ?, updated_at = ?
                 WHERE message_uid = ? AND state <> 'paused'
                """,
                (time.time(), stamp, message_uid),
            )
            if cur.rowcount:
                con.execute(
                    "UPDATE messages SET status = 'Lagt tilbake i utboks', updated_at = ? "
                    "WHERE message_uid = ? AND direction = 'sent'",
                    (stamp, message_uid),
                )
                attempts_row = con.execute(
                    "SELECT attempts FROM outbox WHERE message_uid = ?",
                    (message_uid,),
                ).fetchone()
                self._append_queue_event(
                    con,
                    "waveshare",
                    message_uid,
                    "retry_now",
                    state="queued",
                    attempts=int(attempts_row[0]) if attempts_row else 0,
                    detail="Bruker ba om nytt forsøk nå",
                )
        return cur.rowcount > 0

    def renew_outbox(self, message_uid: str, *, ttl_hours: float) -> bool:
        """Renew one retained user message after its delivery lifetime expired."""
        stamp = now_iso()
        current = time.time()
        expires = current + max(0.1, float(ttl_hours)) * 3600
        with self._connect() as con:
            row = con.execute(
                "SELECT attempts FROM outbox WHERE message_uid = ? AND state = 'expired_hold'",
                (message_uid,),
            ).fetchone()
            if row is None:
                return False
            con.execute(
                """
                UPDATE outbox
                   SET state = 'queued', next_attempt_epoch = ?, expires_epoch = ?,
                       last_error = '', updated_at = ?
                 WHERE message_uid = ? AND state = 'expired_hold'
                """,
                (current, expires, stamp, message_uid),
            )
            con.execute(
                "UPDATE messages SET status = 'Levetid forlenget – lagt tilbake i utboks', "
                "updated_at = ? WHERE message_uid = ? AND direction = 'sent'",
                (stamp, message_uid),
            )
            self._append_queue_event(
                con,
                "waveshare",
                message_uid,
                "renewed",
                state="queued",
                attempts=int(row["attempts"]),
                detail=f"Levetid forlenget med {float(ttl_hours):g} time(r)",
            )
        return True

    def pause_outbox(self, message_uid: str) -> bool:
        stamp = now_iso()
        current = time.time()
        with self._connect() as con:
            cur = con.execute(
                """
                UPDATE outbox
                   SET state = 'paused', paused_at_epoch = ?, updated_at = ?
                 WHERE message_uid = ? AND state IN ('queued', 'retry_wait')
                """,
                (current, stamp, message_uid),
            )
            if cur.rowcount:
                con.execute(
                    "UPDATE messages SET status = 'Pauset i utboks', updated_at = ? "
                    "WHERE message_uid = ? AND direction = 'sent'",
                    (stamp, message_uid),
                )
                attempts_row = con.execute(
                    "SELECT attempts FROM outbox WHERE message_uid = ?",
                    (message_uid,),
                ).fetchone()
                self._append_queue_event(
                    con,
                    "waveshare",
                    message_uid,
                    "paused",
                    state="paused",
                    attempts=int(attempts_row[0]) if attempts_row else 0,
                    detail="Pauset av bruker",
                )
        return cur.rowcount > 0

    def resume_outbox(self, message_uid: str) -> bool:
        stamp = now_iso()
        current = time.time()
        with self._connect() as con:
            row = con.execute(
                "SELECT paused_at_epoch FROM outbox "
                "WHERE message_uid = ? AND state = 'paused'",
                (message_uid,),
            ).fetchone()
            if row is None:
                return False
            paused_at = float(row[0] or current)
            paused_duration = max(0.0, current - paused_at)
            con.execute(
                """
                UPDATE outbox
                   SET state = 'queued', next_attempt_epoch = ?,
                       expires_epoch = expires_epoch + ?, paused_at_epoch = NULL,
                       updated_at = ?
                 WHERE message_uid = ? AND state = 'paused'
                """,
                (current, paused_duration, stamp, message_uid),
            )
            con.execute(
                "UPDATE messages SET status = 'Gjenopptatt i utboks', updated_at = ? "
                "WHERE message_uid = ? AND direction = 'sent'",
                (stamp, message_uid),
            )
            attempts_row = con.execute(
                "SELECT attempts FROM outbox WHERE message_uid = ?",
                (message_uid,),
            ).fetchone()
            self._append_queue_event(
                con,
                "waveshare",
                message_uid,
                "resumed",
                state="queued",
                attempts=int(attempts_row[0]) if attempts_row else 0,
                detail="Gjenopptatt av bruker",
            )
        return True

    def outbox_rows(self) -> list[dict[str, Any]]:
        with self._connect() as con:
            rows = con.execute("SELECT * FROM outbox ORDER BY created_at").fetchall()
        return [dict(row) for row in rows]

    def outbox_counts(self) -> tuple[int, int]:
        with self._connect() as con:
            row = con.execute(
                "SELECT COUNT(*), "
                "COALESCE(SUM(CASE WHEN traffic_class = 'sync' THEN 1 ELSE 0 END), 0) "
                "FROM outbox"
            ).fetchone()
        return int(row[0]), int(row[1])

    def outbox_count(self) -> int:
        return self.outbox_counts()[0]

    def receive_once(
        self, *, message_uid: str, source: int, destination: int,
        text: str, packet_rssi: int | None, raw_hex: str | None,
    ) -> bool:
        """Commit message and replay marker together; return True for a duplicate.

        An existing orphan marker is an explicit error, never an ACK-worthy
        duplicate. No historical records are deleted or globally repaired.
        """
        stamp = now_iso()
        epoch = datetime.fromisoformat(stamp).timestamp()
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            seen = con.execute(
                "SELECT source FROM seen_packets WHERE message_uid = ?",
                (message_uid,),
            ).fetchone()
            row = con.execute(
                "SELECT source, destination, text FROM messages "
                "WHERE message_uid = ? AND direction = 'received' "
                "AND COALESCE(network, 'Waveshare') = 'Waveshare' "
                "AND COALESCE(sync_origin, '') = '' ORDER BY id LIMIT 1",
                (message_uid,),
            ).fetchone()
            if seen is not None and row is None:
                raise RuntimeError("Receive replay marker has no stored message")
            if row is not None and (
                int(row['source']) != source or int(row['destination']) != destination
                or row['text'] != text
            ):
                raise RuntimeError("Receive UID conflicts with stored message")
            if seen is not None and int(seen['source']) != source:
                raise RuntimeError("Receive UID conflicts with replay source")
            duplicate = row is not None
            if not duplicate:
                con.execute(
                    "INSERT INTO messages(message_uid, timestamp, direction, source, "
                    "destination, broadcast, text, packet_rssi, status, raw_hex, "
                    "ack_rssi, attempts, updated_at) "
                    "VALUES (?, ?, 'received', ?, ?, ?, ?, ?, 'Mottatt', ?, NULL, 1, ?)",
                    (message_uid, stamp, source, destination, int(destination == 65535),
                     text, packet_rssi, raw_hex, stamp),
                )
            con.execute(
                "INSERT OR IGNORE INTO seen_packets "
                "(message_uid, first_seen, first_seen_epoch, source) VALUES (?, ?, ?, ?)",
                (message_uid, stamp, epoch, source),
            )
        return duplicate

    def was_seen(self, message_uid: str) -> bool:
        with self._connect() as con:
            row = con.execute(
                "SELECT 1 FROM seen_packets WHERE message_uid = ?", (message_uid,)
            ).fetchone()
        return row is not None

    def mark_seen(self, message_uid: str, source: int) -> None:
        stamp = now_iso()
        first_seen_epoch = datetime.fromisoformat(stamp).timestamp()
        with self._connect() as con:
            con.execute(
                """
                INSERT OR IGNORE INTO seen_packets(
                    message_uid, first_seen, first_seen_epoch, source
                ) VALUES (?, ?, ?, ?)
                """,
                (message_uid, stamp, first_seen_epoch, source),
            )

    def add_received(
        self,
        *,
        message_uid: str,
        source: int,
        destination: int,
        text: str,
        packet_rssi: int | None,
        raw_hex: str | None,
    ) -> int:
        stamp = now_iso()
        with self._connect() as con:
            cur = con.execute(
                """
                INSERT INTO messages(
                    message_uid, timestamp, direction, source, destination,
                    broadcast, text, packet_rssi, status, raw_hex,
                    ack_rssi, attempts, updated_at
                ) VALUES (?, ?, 'received', ?, ?, ?, ?, ?, 'Mottatt', ?, NULL, 1, ?)
                """,
                (
                    message_uid,
                    stamp,
                    source,
                    destination,
                    1 if destination == 65535 else 0,
                    text,
                    packet_rssi,
                    raw_hex,
                    stamp,
                ),
            )
        return int(cur.lastrowid)

    def message_sync_cursor(self, route: str) -> int:
        with self._connect() as con:
            row = con.execute(
                "SELECT remote_sequence FROM message_sync_state WHERE route = ?",
                (route,),
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def set_message_sync_cursor(self, route: str, sequence: int) -> None:
        with self._connect() as con:
            con.execute(
                """
                INSERT INTO message_sync_state(route, remote_sequence, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(route) DO UPDATE SET
                    remote_sequence = MAX(message_sync_state.remote_sequence,
                                          excluded.remote_sequence),
                    updated_at = excluded.updated_at
                """,
                (route, max(0, int(sequence)), now_iso()),
            )

    def upsert_synced_message(self, route: str, payload: dict[str, Any]) -> int:
        """Insert or update one Base message snapshot on Mobile.

        ``message_uid`` and network identify a logical row.  Repeated sync
        events update status and metadata without creating duplicate history.
        """
        message_uid = str(payload.get("message_uid") or "").strip()
        if not message_uid:
            raise ValueError("Synkronisert melding mangler message_uid")
        network = str(payload.get("network") or route)
        timestamp = str(payload.get("timestamp") or now_iso())
        updated_at = str(payload.get("updated_at") or timestamp)
        direction = str(payload.get("direction") or "received")
        source = int(payload.get("source") or 0)
        destination = int(payload.get("destination") or 0)
        broadcast = int(payload.get("broadcast") or 0)
        text = str(payload.get("text") or "")
        packet_rssi = payload.get("packet_rssi")
        ack_rssi = payload.get("ack_rssi")
        attempts = int(payload.get("attempts") or 1)
        status = str(payload.get("status") or "Synkronisert")
        source_label = str(payload.get("source_label") or "")
        destination_label = str(payload.get("destination_label") or "")
        snr = payload.get("snr")
        channel = payload.get("channel")
        gateway_request_id = str(payload.get("gateway_request_id") or "")
        remote_message_id = payload.get("id")
        with self._connect() as con:
            row = con.execute(
                """
                SELECT id FROM messages
                 WHERE message_uid = ?
                   AND (sync_origin = ? OR (sync_origin = '' AND COALESCE(network, 'Waveshare') = ?))
                 ORDER BY id LIMIT 1
                """,
                (message_uid, route, network),
            ).fetchone()
            if row is None:
                cur = con.execute(
                    """
                    INSERT INTO messages(
                        message_uid, timestamp, direction, source, destination,
                        broadcast, text, packet_rssi, status, raw_hex,
                        ack_rssi, attempts, updated_at, network, source_label,
                        destination_label, snr, channel, gateway_request_id,
                        sync_origin, remote_message_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        message_uid, timestamp, direction, source, destination,
                        broadcast, text, packet_rssi, status, ack_rssi, attempts,
                        updated_at, network, source_label, destination_label, snr,
                        channel, gateway_request_id, route,
                        int(remote_message_id) if remote_message_id is not None else None,
                    ),
                )
                return int(cur.lastrowid)
            local_id = int(row[0])
            con.execute(
                """
                UPDATE messages SET
                    timestamp = ?, direction = ?, source = ?, destination = ?,
                    broadcast = ?, text = ?, packet_rssi = ?, status = ?,
                    ack_rssi = ?, attempts = ?, updated_at = ?, network = ?,
                    source_label = ?, destination_label = ?, snr = ?, channel = ?,
                    gateway_request_id = ?, sync_origin = ?, remote_message_id = ?
                 WHERE id = ?
                """,
                (
                    timestamp, direction, source, destination, broadcast, text,
                    packet_rssi, status, ack_rssi, attempts, updated_at, network,
                    source_label, destination_label, snr, channel,
                    gateway_request_id, route,
                    int(remote_message_id) if remote_message_id is not None else None,
                    local_id,
                ),
            )
        return local_id

    def tag_gateway_request(self, message_uid: str, request_id: str) -> bool:
        """Associate a durable Waveshare carrier row with one logical gateway request."""
        if not message_uid or not request_id:
            return False
        with self._connect() as con:
            cur = con.execute(
                "UPDATE messages SET gateway_request_id = ?, updated_at = ? "
                "WHERE message_uid = ?",
                (request_id, now_iso(), message_uid),
            )
        return cur.rowcount > 0

    def gateway_request_exists(self, request_id: str) -> bool:
        if not request_id:
            return False
        with self._connect() as con:
            row = con.execute(
                "SELECT 1 FROM messages WHERE gateway_request_id = ? LIMIT 1",
                (request_id,),
            ).fetchone()
        return row is not None

    def apply_synced_gateway_status(
        self, request_id: str, payload: dict[str, Any]
    ) -> int:
        """Persist a Base-side gateway status on the local SEND carrier row.

        Mobile and Base use different message UIDs for the private Waveshare
        carrier and the logical Meshtastic message.  ``gateway_request_id`` is
        therefore the stable identity used to carry later queue/ACK status
        changes back to the already visible Mobile row.
        """
        if not request_id:
            return 0
        status = str(payload.get("status") or "Synkronisert")
        updated_at = str(payload.get("updated_at") or now_iso())
        attempts = payload.get("attempts")
        ack_rssi = payload.get("ack_rssi")
        with self._connect() as con:
            if attempts is None:
                cur = con.execute(
                    """
                    UPDATE messages
                       SET status = ?, updated_at = ?,
                           ack_rssi = COALESCE(?, ack_rssi)
                     WHERE gateway_request_id = ? AND direction = 'sent'
                    """,
                    (status, updated_at, ack_rssi, request_id),
                )
            else:
                cur = con.execute(
                    """
                    UPDATE messages
                       SET status = ?, updated_at = ?, attempts = ?,
                           ack_rssi = COALESCE(?, ack_rssi)
                     WHERE gateway_request_id = ? AND direction = 'sent'
                    """,
                    (
                        status, updated_at, max(1, int(attempts)), ack_rssi,
                        request_id,
                    ),
                )
        return int(cur.rowcount)

    def list_recent(self, limit: int = 500) -> list[dict[str, Any]]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM messages ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def list_recent_controls(self, limit: int = 500) -> list[dict[str, Any]]:
        """Return recent internal LC2/LC3 carrier rows.

        Control traffic is fetched separately from user-visible history so a
        burst of node/status/synchronisation frames cannot push ordinary chat
        messages out of the GUI's fixed-size history window.
        """
        with self._connect() as con:
            rows = con.execute(
                """
                SELECT * FROM messages
                 WHERE text LIKE '~LC2|%' OR text LIKE '~L3|%'
                 ORDER BY id DESC
                 LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def list_recent_display_carriers(
        self, limit: int = 250, *, before_id: int | None = None
    ) -> list[dict[str, Any]]:
        """Return rows that can produce visible chat history.

        Ordinary messages are selected before applying ``LIMIT``.  Sent
        gateway messages remain represented by their tagged LC2/LC3 carrier
        rows (``gateway_request_id``), and legacy LC2 inbound MESHIN rows are
        retained for backwards-compatible history.  Other internal control
        traffic is excluded before the limit is applied.  ``before_id`` lets
        the GUI request an older page only when fragmented carrier rows mean
        that one page contains fewer logical messages than requested.
        """
        boundary = int(before_id) if before_id is not None else None
        with self._connect() as con:
            rows = con.execute(
                """
                SELECT * FROM messages
                 WHERE (
                        COALESCE(gateway_request_id, '') <> ''
                     OR (text NOT LIKE '~LC2|%' AND text NOT LIKE '~L3|%')
                     OR (direction = 'received' AND text LIKE '~LC2|MESHIN|%')
                 )
                   AND (? IS NULL OR id < ?)
                 ORDER BY id DESC
                 LIMIT ?
                """,
                (boundary, boundary, limit),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

