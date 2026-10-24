#!/usr/bin/env python3
from __future__ import annotations

from contextlib import contextmanager

import argparse
import json
import logging
import signal
import socket
import socketserver
import sqlite3
import threading
import time
import uuid
import zlib
from datetime import datetime
from pathlib import Path
from typing import Any

from api_security import is_loopback_client
from capabilities import network_capability_allowed, runtime_capability_view

from mesh_receive_health import observed_interface_class, receive_health_snapshot, transport_failure

import meshtastic.serial_interface
from pubsub import pub

from message_store import MessageStore
from lc3_replay_store import LC3ReplayStore
from node_catalog import NodeCatalog
from position_store import PositionStore
from protocol import (
    ControlAuthenticator,
    canonical_meshtastic_id,
    destination_to_num,
    encode_gateway_ack,
    encode_gateway_delivered,
    encode_gateway_error,
    encode_gateway_nak,
    encode_gateway_queued,
    encode_gateway_identity,
    encode_info,
    encode_mesh_in,
    encode_message_done,
    encode_message_sync,
    encode_position_history_done,
    encode_position_history_sync,
    encode_position_sync,
    encode_positions_done,
    encode_node,
    encode_nodes_done,
    fragment_frame,
    parse_control,
    control_transport_policy,
    parse_routing_result,
)


from sqlite_resilience import sqlite_locked_retry

LOG = logging.getLogger("meshbridge")
BROADCAST_NUM = 0xFFFFFFFF
APP_VERSION = "2.5.0-beta5"


ObservedSerialInterface = observed_interface_class(meshtastic.serial_interface.SerialInterface)

def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def json_api_call(host: str, port: int, request: dict[str, Any]) -> dict[str, Any]:
    data = (json.dumps(request, ensure_ascii=False) + "\n").encode("utf-8")
    with socket.create_connection((host, port), timeout=3.0) as sock:
        sock.sendall(data)
        response = json.loads(sock.makefile("rb").readline().decode("utf-8"))
    if not response.get("ok"):
        raise RuntimeError(response.get("error", "Ukjent API-feil"))
    return response


class BridgeStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_journal()
        # Ensure the shared message table exists even when systemd happens to
        # start a Meshtastic bridge before lorad has initialized the database.
        MessageStore(self.db_path)
        self._init_db()

    def _initialize_journal(self) -> None:
        """OFFLINE REVIEW: establish WAL at startup, closing on every exit."""
        def initialize() -> None:
            con = sqlite3.connect(self.db_path, timeout=10)
            try:
                con.execute("PRAGMA busy_timeout=5000")
                mode = con.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                if str(mode).lower() != "wal":
                    raise RuntimeError("BridgeStore WAL initialization failed")
            finally:
                con.close()

        sqlite_locked_retry(
            initialize, label="BridgeStore WAL initialization", logger=LOG
        )

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=10)
        try:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA busy_timeout=5000")
            mode = con.execute("PRAGMA journal_mode").fetchone()[0]
            if str(mode).lower() != "wal":
                raise RuntimeError("BridgeStore requires initialized WAL")
            return con
        except BaseException:
            con.close()
            raise

    @contextmanager
    def _connection(self):
        """OFFLINE REVIEW: finish transaction and close deterministically."""
        con = self._connect()
        try:
            with con:
                yield con
        finally:
            con.close()

    @staticmethod
    def _columns(con: sqlite3.Connection, table: str) -> set[str]:
        return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table})")}

    def _init_db(self) -> None:
        with self._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            columns = self._columns(con, "messages")
            additions = {
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
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS bridge_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS mesh_pending (
                    packet_id TEXT PRIMARY KEY,
                    message_uid TEXT NOT NULL,
                    route TEXT NOT NULL,
                    request_id TEXT NOT NULL DEFAULT '',
                    waveshare_source INTEGER,
                    destination TEXT NOT NULL,
                    deadline_epoch REAL NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_network ON messages(network)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_mesh_pending_deadline "
                "ON mesh_pending(deadline_epoch)"
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS gateway_outbox (
                    request_id TEXT PRIMARY KEY,
                    route TEXT NOT NULL,
                    waveshare_source INTEGER,
                    destination TEXT NOT NULL,
                    channel INTEGER NOT NULL,
                    text TEXT NOT NULL,
                    source_label TEXT NOT NULL,
                    protocol TEXT NOT NULL DEFAULT 'LC3',
                    state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    packet_id TEXT NOT NULL DEFAULT '',
                    next_attempt_epoch REAL NOT NULL,
                    expires_epoch REAL NOT NULL,
                    last_error TEXT NOT NULL DEFAULT '',
                    message_uid TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            gateway_columns = self._columns(con, "gateway_outbox")
            gateway_additions = {
                "priority": "INTEGER NOT NULL DEFAULT 100",
                "paused_at_epoch": "REAL",
                "last_attempt_epoch": "REAL",
            }
            for name, definition in gateway_additions.items():
                if name not in gateway_columns:
                    con.execute(
                        f"ALTER TABLE gateway_outbox ADD COLUMN {name} {definition}"
                    )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_gateway_outbox_due "
                "ON gateway_outbox(route, state, next_attempt_epoch)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_gateway_outbox_expiry "
                "ON gateway_outbox(route, expires_epoch)"
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS message_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    route TEXT NOT NULL,
                    message_uid TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_message_events_route_sequence "
                "ON message_events(route, sequence)"
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS control_fragments (
                    route TEXT NOT NULL,
                    waveshare_source INTEGER NOT NULL,
                    transfer_id TEXT NOT NULL,
                    fragment_index INTEGER NOT NULL,
                    fragment_count INTEGER NOT NULL,
                    crc TEXT NOT NULL,
                    payload_text TEXT NOT NULL,
                    created_epoch REAL NOT NULL,
                    PRIMARY KEY(route, waveshare_source, transfer_id, fragment_index)
                )
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_control_fragments_expiry "
                "ON control_fragments(created_epoch)"
            )

    @staticmethod
    def _append_queue_event(
        con: sqlite3.Connection,
        route: str,
        request_id: str,
        event_type: str,
        *,
        state: str = "",
        attempts: int = 0,
        detail: str = "",
    ) -> None:
        """Append privacy-safe Base-queue history without message text."""
        con.execute(
            """
            INSERT INTO queue_events(
                queue_kind, item_id, event_type, state, attempts, detail,
                occurred_at, occurred_epoch
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"gateway:{route}",
                str(request_id),
                str(event_type),
                str(state),
                max(0, int(attempts)),
                str(detail or "")[:500],
                now_iso(),
                time.time(),
            ),
        )

    def gateway_queue_history(
        self, request_id: str, route: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 200))
        with self._connection() as con:
            rows = con.execute(
                """
                SELECT sequence, event_type, state, attempts, detail,
                       occurred_at, occurred_epoch
                  FROM queue_events
                 WHERE queue_kind = ? AND item_id = ?
                 ORDER BY sequence DESC
                 LIMIT ?
                """,
                (f"gateway:{route}", str(request_id), safe_limit),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def add_control_fragment(
        self,
        *,
        route: str,
        waveshare_source: int,
        control: dict[str, Any],
        ttl_seconds: float = 300.0,
        max_fragments: int = 4,
    ) -> str | None:
        """Persist and reassemble one LC3 fragment series.

        Mobile→Base transfers may span several durable Waveshare messages.
        Persisting the parts prevents a Base bridge restart between fragments
        from silently losing the logical command.
        """
        transfer_id = str(control.get("transfer_id") or "")
        index = int(control.get("index", 0))
        count = int(control.get("count", 0))
        crc = str(control.get("crc") or "").lower()
        payload = control.get("payload_text")
        hex_chars = frozenset("0123456789abcdef")
        if (
            not 1 <= len(transfer_id) <= 12
            or any(char.lower() not in hex_chars for char in transfer_id)
            or len(crc) != 8
            or any(char not in hex_chars for char in crc)
            or not isinstance(payload, str)
        ):
            raise ValueError("Fragmentet har ugyldig identitet, CRC eller nyttelast")
        if count < 2 or count > max(1, int(max_fragments)) or not 1 <= index <= count:
            raise ValueError("Ugyldig fragmentnummer eller antall")
        current = time.time()
        cutoff = current - max(5.0, float(ttl_seconds))
        with self._connection() as con:
            con.execute("DELETE FROM control_fragments WHERE created_epoch < ?", (cutoff,))
            metadata = con.execute(
                """
                SELECT fragment_count, crc FROM control_fragments
                 WHERE route = ? AND waveshare_source = ? AND transfer_id = ?
                 LIMIT 1
                """,
                (route, int(waveshare_source), transfer_id),
            ).fetchone()
            if metadata is not None and (
                int(metadata["fragment_count"]) != count
                or str(metadata["crc"]).lower() != crc
            ):
                con.execute(
                    "DELETE FROM control_fragments WHERE route = ? "
                    "AND waveshare_source = ? AND transfer_id = ?",
                    (route, int(waveshare_source), transfer_id),
                )
                raise ValueError("Fragmentserien endret antall eller kontrollsum")
            con.execute(
                """
                INSERT INTO control_fragments(
                    route, waveshare_source, transfer_id, fragment_index,
                    fragment_count, crc, payload_text, created_epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(route, waveshare_source, transfer_id, fragment_index)
                DO UPDATE SET payload_text = excluded.payload_text,
                              created_epoch = excluded.created_epoch
                """,
                (route, int(waveshare_source), transfer_id, index, count, crc, payload, current),
            )
            rows = con.execute(
                """
                SELECT fragment_index, payload_text FROM control_fragments
                 WHERE route = ? AND waveshare_source = ? AND transfer_id = ?
                 ORDER BY fragment_index
                """,
                (route, int(waveshare_source), transfer_id),
            ).fetchall()
            if len(rows) != count:
                return None
            positions = [int(row["fragment_index"]) for row in rows]
            if positions != list(range(1, count + 1)):
                return None
            complete = "".join(str(row["payload_text"]) for row in rows)
            actual = f"{zlib.crc32(complete.encode('utf-8')) & 0xFFFFFFFF:08x}"
            con.execute(
                "DELETE FROM control_fragments WHERE route = ? "
                "AND waveshare_source = ? AND transfer_id = ?",
                (route, int(waveshare_source), transfer_id),
            )
            if actual != crc:
                raise ValueError("CRC-feil i sammensatt LC3-kontrollmelding")
            return complete

    def get_state(self, key: str) -> str | None:
        with self._connection() as con:
            row = con.execute(
                "SELECT value FROM bridge_state WHERE key = ?", (key,)
            ).fetchone()
        return str(row[0]) if row is not None else None

    def set_state(self, key: str, value: str) -> None:
        with self._connection() as con:
            con.execute(
                """
                INSERT INTO bridge_state(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, str(value)),
            )

    def get_state_int(self, key: str) -> int | None:
        value = self.get_state(key)
        return int(value) if value is not None else None

    def set_state_int(self, key: str, value: int) -> None:
        with self._connection() as con:
            con.execute(
                """
                INSERT INTO bridge_state(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, str(value)),
            )

    def max_message_id(self) -> int:
        with self._connection() as con:
            row = con.execute("SELECT COALESCE(MAX(id), 0) FROM messages").fetchone()
        return int(row[0])

    def next_received_waveshare(self, after_id: int) -> dict[str, Any] | None:
        with self._connection() as con:
            row = con.execute(
                """
                SELECT * FROM messages
                 WHERE id > ?
                   AND direction = 'received'
                   AND COALESCE(network, 'Waveshare') = 'Waveshare'
                 ORDER BY id ASC
                 LIMIT 1
                """,
                (after_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    @staticmethod
    def _message_payload(con: sqlite3.Connection, message_uid: str) -> dict[str, Any] | None:
        row = con.execute(
            "SELECT * FROM messages WHERE message_uid = ? ORDER BY id LIMIT 1",
            (message_uid,),
        ).fetchone()
        return dict(row) if row is not None else None

    @classmethod
    def _append_message_event(
        cls,
        con: sqlite3.Connection,
        route: str,
        message_uid: str,
        event_type: str,
    ) -> None:
        payload = cls._message_payload(con, message_uid)
        if payload is None:
            return
        # Raw radio frames are not useful to Mobile and consume scarce airtime.
        payload.pop("raw_hex", None)
        con.execute(
            """
            INSERT INTO message_events(
                route, message_uid, event_type, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                route,
                message_uid,
                event_type,
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                now_iso(),
            ),
        )

    def add_meshtastic(
        self,
        *,
        message_uid: str,
        direction: str,
        source: int,
        destination: int,
        source_label: str,
        destination_label: str,
        text: str,
        packet_rssi: int | None,
        snr: float | None,
        channel: int,
        status: str,
        network: str,
        route: str,
        raw_hex: str | None = None,
        gateway_request_id: str = "",
        attempts: int = 1,
    ) -> int:
        """Insert or refresh one logical Meshtastic message and append a sync event."""
        timestamp = now_iso()
        with self._connection() as con:
            existing = con.execute(
                "SELECT id, timestamp FROM messages WHERE message_uid = ? ORDER BY id LIMIT 1",
                (message_uid,),
            ).fetchone()
            if existing is None:
                cur = con.execute(
                    """
                    INSERT INTO messages
                    (message_uid, timestamp, direction, source, destination,
                     broadcast, text, packet_rssi, status, raw_hex,
                     ack_rssi, attempts, updated_at, network, source_label,
                     destination_label, snr, channel, gateway_request_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?,
                            ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        message_uid,
                        timestamp,
                        direction,
                        source,
                        destination,
                        1 if destination == BROADCAST_NUM else 0,
                        text,
                        packet_rssi,
                        status,
                        raw_hex,
                        max(1, int(attempts)),
                        timestamp,
                        network,
                        source_label,
                        destination_label,
                        snr,
                        channel,
                        gateway_request_id,
                    ),
                )
                message_id = int(cur.lastrowid)
                event_type = "created"
            else:
                message_id = int(existing["id"])
                con.execute(
                    """
                    UPDATE messages SET
                        direction = ?, source = ?, destination = ?, broadcast = ?,
                        text = ?, packet_rssi = COALESCE(?, packet_rssi),
                        status = ?, raw_hex = COALESCE(?, raw_hex), attempts = ?,
                        updated_at = ?, network = ?, source_label = ?,
                        destination_label = ?, snr = COALESCE(?, snr), channel = ?,
                        gateway_request_id = CASE WHEN ? = '' THEN gateway_request_id ELSE ? END
                     WHERE id = ?
                    """,
                    (
                        direction,
                        source,
                        destination,
                        1 if destination == BROADCAST_NUM else 0,
                        text,
                        packet_rssi,
                        status,
                        raw_hex,
                        max(1, int(attempts)),
                        timestamp,
                        network,
                        source_label,
                        destination_label,
                        snr,
                        channel,
                        gateway_request_id,
                        gateway_request_id,
                        message_id,
                    ),
                )
                event_type = "updated"
            self._append_message_event(con, route, message_uid, event_type)
        return message_id

    def update_message_status(
        self,
        message_uid: str,
        status: str,
        *,
        route: str,
        attempts: int | None = None,
    ) -> bool:
        with self._connection() as con:
            if attempts is None:
                cur = con.execute(
                    "UPDATE messages SET status = ?, updated_at = ? WHERE message_uid = ?",
                    (status, now_iso(), message_uid),
                )
            else:
                cur = con.execute(
                    "UPDATE messages SET status = ?, attempts = ?, updated_at = ? "
                    "WHERE message_uid = ?",
                    (status, max(1, int(attempts)), now_iso(), message_uid),
                )
            if cur.rowcount:
                self._append_message_event(con, route, message_uid, "status")
        return cur.rowcount > 0

    @staticmethod
    def _pending_key(route: str, packet_id: str) -> str:
        # B868 and B433 can independently allocate the same numeric packet ID.
        # Prefixing with the route avoids one bridge replacing the other's row
        # in the shared SQLite database while keeping the existing schema.
        return f"{route}:{packet_id}"

    @staticmethod
    def _pending_radio_id(route: str, stored_id: str) -> str:
        prefix = f"{route}:"
        return stored_id[len(prefix) :] if stored_id.startswith(prefix) else stored_id

    def add_pending(
        self,
        *,
        packet_id: str,
        message_uid: str,
        route: str,
        request_id: str,
        waveshare_source: int | None,
        destination: str | int,
        deadline_epoch: float,
    ) -> None:
        key = self._pending_key(route, packet_id)
        with self._connection() as con:
            con.execute(
                """
                INSERT OR REPLACE INTO mesh_pending(
                    packet_id, message_uid, route, request_id, waveshare_source,
                    destination, deadline_epoch, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key,
                    message_uid,
                    route,
                    request_id,
                    waveshare_source,
                    str(destination),
                    deadline_epoch,
                    now_iso(),
                ),
            )

    def pop_pending(self, packet_id: str, route: str) -> dict[str, Any] | None:
        key = self._pending_key(route, packet_id)
        with self._connection() as con:
            # The raw-ID fallback consumes an unfinished beta3a row during the
            # first 2.1 startup without making it permanently incompatible.
            row = con.execute(
                "SELECT * FROM mesh_pending WHERE route = ? "
                "AND packet_id IN (?, ?) ORDER BY packet_id = ? DESC LIMIT 1",
                (route, key, packet_id, key),
            ).fetchone()
            if row is not None:
                con.execute(
                    "DELETE FROM mesh_pending WHERE packet_id = ?",
                    (str(row["packet_id"]),),
                )
        if row is None:
            return None
        result = dict(row)
        result["packet_id"] = packet_id
        return result

    def expire_pending(self, route: str) -> list[dict[str, Any]]:
        current = time.time()
        with self._connection() as con:
            rows = con.execute(
                "SELECT * FROM mesh_pending WHERE route = ? AND deadline_epoch <= ?",
                (route, current),
            ).fetchall()
            con.execute(
                "DELETE FROM mesh_pending WHERE route = ? AND deadline_epoch <= ?",
                (route, current),
            )
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["packet_id"] = self._pending_radio_id(
                str(item.get("route", "")), str(item.get("packet_id", ""))
            )
            result.append(item)
        return result

    def interrupt_pending(self, route: str) -> list[dict[str, Any]]:
        with self._connection() as con:
            rows = con.execute(
                "SELECT * FROM mesh_pending WHERE route = ?", (route,)
            ).fetchall()
            con.execute("DELETE FROM mesh_pending WHERE route = ?", (route,))
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["packet_id"] = self._pending_radio_id(
                str(item.get("route", "")), str(item.get("packet_id", ""))
            )
            result.append(item)
        return result

    def seed_message_events(self, route: str, network: str) -> int:
        """Create one initial snapshot event for pre-2.1 Meshtastic rows."""
        created = 0
        with self._connection() as con:
            rows = con.execute(
                """
                SELECT message_uid FROM messages m
                 WHERE COALESCE(network, 'Waveshare') = ?
                   AND NOT EXISTS (
                       SELECT 1 FROM message_events e
                        WHERE e.route = ? AND e.message_uid = m.message_uid
                   )
                 ORDER BY id
                """,
                (network, route),
            ).fetchall()
            for row in rows:
                self._append_message_event(con, route, str(row["message_uid"]), "seed")
                created += 1
        return created

    def message_events_since(
        self, route: str, sequence: int, limit: int
    ) -> tuple[list[dict[str, Any]], bool]:
        safe_limit = max(1, min(int(limit), 50))
        with self._connection() as con:
            rows = con.execute(
                """
                SELECT sequence, event_type, payload_json, created_at
                  FROM message_events
                 WHERE route = ? AND sequence > ?
                 ORDER BY sequence ASC
                 LIMIT ?
                """,
                (route, max(0, int(sequence)), safe_limit + 1),
            ).fetchall()
        more = len(rows) > safe_limit
        rows = rows[:safe_limit]
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                result.append(
                    {
                        "sequence": int(row["sequence"]),
                        "event_type": str(row["event_type"]),
                        "payload": payload,
                        "created_at": str(row["created_at"]),
                    }
                )
        return result, more

    def enqueue_gateway_request(
        self,
        *,
        request_id: str,
        route: str,
        waveshare_source: int | None,
        destination: str | int,
        channel: int,
        text: str,
        source_label: str,
        protocol: str,
        ttl_hours: float,
        priority: int = 100,
        max_pending: int | None = None,
    ) -> tuple[dict[str, Any], bool]:
        current = time.time()
        stamp = now_iso()
        message_uid = f"gw-{route}-{request_id}"
        with self._connection() as con:
            existing = con.execute(
                "SELECT * FROM gateway_outbox WHERE request_id = ?", (request_id,)
            ).fetchone()
            if existing is not None:
                return dict(existing), False
            if max_pending is not None:
                pending_count = int(
                    con.execute(
                        "SELECT COUNT(*) FROM gateway_outbox WHERE route = ? "
                        "AND state NOT IN ('delivered', 'sent', 'failed')",
                        (route,),
                    ).fetchone()[0]
                )
                if pending_count >= max(1, int(max_pending)):
                    raise RuntimeError(
                        f"Base-køen er full ({pending_count}/{int(max_pending)} poster)"
                    )
            effective_priority = max(0, min(int(priority), 1000))
            con.execute(
                """
                INSERT INTO gateway_outbox(
                    request_id, route, waveshare_source, destination, channel,
                    text, source_label, protocol, state, attempts, packet_id,
                    next_attempt_epoch, expires_epoch, last_error, message_uid,
                    created_at, updated_at, priority, paused_at_epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', 0, '', ?, ?, '', ?, ?, ?, ?, NULL)
                """,
                (
                    request_id,
                    route,
                    waveshare_source,
                    str(destination),
                    int(channel),
                    text,
                    source_label,
                    protocol,
                    current,
                    current + max(0.1, float(ttl_hours)) * 3600,
                    message_uid,
                    stamp,
                    stamp,
                    effective_priority,
                ),
            )
            row = con.execute(
                "SELECT * FROM gateway_outbox WHERE request_id = ?", (request_id,)
            ).fetchone()
            self._append_queue_event(
                con,
                route,
                request_id,
                "queued",
                state="queued",
                detail="Lagt i varig Meshtastic Base-kø",
            )
        assert row is not None
        return dict(row), True

    def gateway_request(self, request_id: str) -> dict[str, Any] | None:
        with self._connection() as con:
            row = con.execute(
                "SELECT * FROM gateway_outbox WHERE request_id = ?", (request_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def recover_gateway_outbox(self, route: str) -> int:
        stamp = now_iso()
        current = time.time()
        with self._connection() as con:
            rows = con.execute(
                """
                SELECT request_id, message_uid FROM gateway_outbox
                 WHERE route = ? AND state IN ('sending', 'waiting_ack')
                """,
                (route,),
            ).fetchall()
            con.execute(
                """
                UPDATE gateway_outbox
                   SET state = 'queued', next_attempt_epoch = ?, packet_id = '',
                       last_error = 'gjenopptatt etter omstart', updated_at = ?
                 WHERE route = ? AND state IN ('sending', 'waiting_ack')
                """,
                (current, stamp, route),
            )
            for row in rows:
                con.execute(
                    "UPDATE messages SET status = ?, updated_at = ? WHERE message_uid = ?",
                    ("Base-kø gjenopptatt etter omstart", stamp, str(row["message_uid"])),
                )
                self._append_message_event(
                    con, route, str(row["message_uid"]), "queue_recovered"
                )
                self._append_queue_event(
                    con,
                    route,
                    str(row["request_id"]),
                    "recovered",
                    state="queued",
                    detail="Gjenopptatt etter tjenesteomstart",
                )
        return len(rows)

    def expire_gateway_requests(self, route: str) -> list[dict[str, Any]]:
        current = time.time()
        stamp = now_iso()
        with self._connection() as con:
            rows = con.execute(
                """
                SELECT * FROM gateway_outbox
                 WHERE route = ? AND state NOT IN ('delivered', 'sent', 'failed', 'expired_hold')
                   AND state <> 'paused'
                   AND expires_epoch <= ?
                """,
                (route, current),
            ).fetchall()
            for row in rows:
                con.execute(
                    """
                    UPDATE gateway_outbox SET state = 'expired_hold',
                           last_error = 'levetid utløpt – beholdt for manuell forlengelse',
                           updated_at = ?
                     WHERE request_id = ?
                    """,
                    (stamp, str(row["request_id"])),
                )
                con.execute(
                    "UPDATE messages SET status = ?, updated_at = ? WHERE message_uid = ?",
                    (
                        "Levetid utløpt – beholdt i Base-kø",
                        stamp,
                        str(row["message_uid"]),
                    ),
                )
                self._append_message_event(
                    con, route, str(row["message_uid"]), "queue_expired"
                )
                self._append_queue_event(
                    con,
                    route,
                    str(row["request_id"]),
                    "expired_hold",
                    state="expired_hold",
                    attempts=int(row["attempts"]),
                    detail="Levetid utløpt; meldingen er beholdt i Base-kø",
                )
            updated_rows = []
            for row in rows:
                updated = con.execute(
                    "SELECT * FROM gateway_outbox WHERE request_id = ?",
                    (str(row["request_id"]),),
                ).fetchone()
                if updated is not None:
                    updated_rows.append(dict(updated))
        return updated_rows

    def next_gateway_due(self, route: str) -> dict[str, Any] | None:
        with self._connection() as con:
            row = con.execute(
                """
                SELECT * FROM gateway_outbox
                 WHERE route = ? AND state IN ('queued', 'retry_wait')
                   AND next_attempt_epoch <= ? AND expires_epoch > ?
                 ORDER BY priority DESC, next_attempt_epoch, created_at LIMIT 1
                """,
                (route, time.time(), time.time()),
            ).fetchone()
        return dict(row) if row is not None else None

    def mark_gateway_sending(self, request_id: str) -> int:
        stamp = now_iso()
        current = time.time()
        with self._connection() as con:
            row = con.execute(
                "SELECT attempts, message_uid, route FROM gateway_outbox WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise KeyError(request_id)
            attempts = int(row["attempts"]) + 1
            con.execute(
                """
                UPDATE gateway_outbox SET state = 'sending', attempts = ?,
                       last_attempt_epoch = ?, last_error = '', updated_at = ?
                 WHERE request_id = ?
                """,
                (attempts, current, stamp, request_id),
            )
            con.execute(
                "UPDATE messages SET status = ?, attempts = ?, updated_at = ? "
                "WHERE message_uid = ?",
                (f"Base sender – forsøk {attempts}", attempts, stamp, str(row["message_uid"])),
            )
            self._append_message_event(
                con, str(row["route"]), str(row["message_uid"]), "queue_sending"
            )
            self._append_queue_event(
                con,
                str(row["route"]),
                request_id,
                "sending",
                state="sending",
                attempts=attempts,
                detail=f"Sender forsøk {attempts}",
            )
        return attempts

    def mark_gateway_waiting(self, request_id: str, packet_id: str, status: str) -> None:
        stamp = now_iso()
        with self._connection() as con:
            row = con.execute(
                "SELECT route, message_uid FROM gateway_outbox WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                return
            con.execute(
                """
                UPDATE gateway_outbox SET state = 'waiting_ack', packet_id = ?,
                       updated_at = ? WHERE request_id = ?
                """,
                (packet_id, stamp, request_id),
            )
            con.execute(
                "UPDATE messages SET status = ?, updated_at = ? WHERE message_uid = ?",
                (status, stamp, str(row["message_uid"])),
            )
            self._append_message_event(
                con, str(row["route"]), str(row["message_uid"]), "queue_waiting"
            )
            attempts_row = con.execute(
                "SELECT attempts FROM gateway_outbox WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            self._append_queue_event(
                con,
                str(row["route"]),
                request_id,
                "waiting_ack",
                state="waiting_ack",
                attempts=int(attempts_row[0]) if attempts_row else 0,
                detail=status,
            )

    def schedule_gateway_retry(
        self,
        request_id: str,
        *,
        delay_seconds: float,
        error: str,
        status: str,
    ) -> dict[str, Any] | None:
        stamp = now_iso()
        with self._connection() as con:
            row = con.execute(
                "SELECT * FROM gateway_outbox WHERE request_id = ?", (request_id,)
            ).fetchone()
            if row is None:
                return None
            next_attempt = time.time() + max(0.0, float(delay_seconds))
            con.execute(
                """
                UPDATE gateway_outbox SET state = 'retry_wait', packet_id = '',
                       next_attempt_epoch = ?, last_error = ?, updated_at = ?
                 WHERE request_id = ?
                """,
                (next_attempt, error[:500], stamp, request_id),
            )
            con.execute(
                "UPDATE messages SET status = ?, updated_at = ? WHERE message_uid = ?",
                (status, stamp, str(row["message_uid"])),
            )
            self._append_message_event(
                con, str(row["route"]), str(row["message_uid"]), "queue_retry"
            )
            self._append_queue_event(
                con,
                str(row["route"]),
                request_id,
                "retry_wait",
                state="retry_wait",
                attempts=int(row["attempts"]),
                detail=error or status,
            )
            updated = con.execute(
                "SELECT * FROM gateway_outbox WHERE request_id = ?", (request_id,)
            ).fetchone()
        return dict(updated) if updated is not None else None

    def complete_gateway_request(
        self,
        request_id: str,
        *,
        state: str,
        status: str,
        error: str = "",
    ) -> dict[str, Any] | None:
        stamp = now_iso()
        with self._connection() as con:
            row = con.execute(
                "SELECT * FROM gateway_outbox WHERE request_id = ?", (request_id,)
            ).fetchone()
            if row is None:
                return None
            con.execute(
                """
                UPDATE gateway_outbox SET state = ?, last_error = ?, updated_at = ?
                 WHERE request_id = ?
                """,
                (state, error[:500], stamp, request_id),
            )
            con.execute(
                "UPDATE messages SET status = ?, updated_at = ? WHERE message_uid = ?",
                (status, stamp, str(row["message_uid"])),
            )
            self._append_message_event(
                con, str(row["route"]), str(row["message_uid"]), f"queue_{state}"
            )
            self._append_queue_event(
                con,
                str(row["route"]),
                request_id,
                "completed" if state in {"delivered", "sent"} else state,
                state=state,
                attempts=int(row["attempts"]),
                detail=error or status,
            )
            updated = con.execute(
                "SELECT * FROM gateway_outbox WHERE request_id = ?", (request_id,)
            ).fetchone()
        return dict(updated) if updated is not None else None

    def gateway_counts(self, route: str) -> dict[str, int]:
        with self._connection() as con:
            rows = con.execute(
                "SELECT state, COUNT(*) AS count FROM gateway_outbox "
                "WHERE route = ? GROUP BY state",
                (route,),
            ).fetchall()
        values = {str(row["state"]): int(row["count"]) for row in rows}
        values["pending"] = sum(
            count for state, count in values.items()
            if state not in {"delivered", "sent", "failed", "expired_hold", "pending"}
        )
        values["held"] = int(values.get("expired_hold", 0))
        return values

    def gateway_outbox_rows(self, route: str) -> list[dict[str, Any]]:
        """Return queue metadata only; message text is deliberately omitted."""
        with self._connection() as con:
            rows = con.execute(
                """
                SELECT request_id, route, waveshare_source, destination, channel,
                       protocol, state, attempts, packet_id, next_attempt_epoch,
                       expires_epoch, last_error, message_uid, created_at, updated_at,
                       priority, paused_at_epoch, last_attempt_epoch
                  FROM gateway_outbox
                 WHERE route = ?
                   AND state NOT IN ('delivered', 'sent', 'failed')
                 ORDER BY created_at
                """,
                (route,),
            ).fetchall()
        return [dict(row) for row in rows]

    def retry_gateway_request(self, request_id: str, route: str) -> bool:
        stamp = now_iso()
        current = time.time()
        with self._connection() as con:
            cur = con.execute(
                """
                UPDATE gateway_outbox
                   SET state = 'queued', next_attempt_epoch = ?, last_error = '',
                       updated_at = ?
                 WHERE request_id = ? AND route = ? AND expires_epoch > ?
                   AND state NOT IN ('delivered', 'sent', 'failed', 'paused')
                """,
                (current, stamp, request_id, route, current),
            )
            if cur.rowcount:
                row = con.execute(
                    "SELECT message_uid, attempts FROM gateway_outbox WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if row is not None:
                    con.execute(
                        "UPDATE messages SET status = 'Lagt tilbake i Base-kø', updated_at = ? "
                        "WHERE message_uid = ?",
                        (stamp, str(row[0])),
                    )
                    self._append_queue_event(
                        con,
                        route,
                        request_id,
                        "retry_now",
                        state="queued",
                        attempts=int(row["attempts"]),
                        detail="Bruker ba om nytt forsøk nå",
                    )
        return cur.rowcount > 0

    def renew_gateway_request(
        self,
        request_id: str,
        route: str,
        *,
        ttl_hours: float,
    ) -> bool:
        """Renew a retained Base-queue message after its lifetime expired."""
        stamp = now_iso()
        current = time.time()
        expires = current + max(0.1, float(ttl_hours)) * 3600
        with self._connection() as con:
            row = con.execute(
                "SELECT message_uid, attempts FROM gateway_outbox "
                "WHERE request_id = ? AND route = ? AND state = 'expired_hold'",
                (request_id, route),
            ).fetchone()
            if row is None:
                return False
            con.execute(
                """
                UPDATE gateway_outbox
                   SET state = 'queued', next_attempt_epoch = ?, expires_epoch = ?,
                       last_error = '', updated_at = ?
                 WHERE request_id = ? AND route = ? AND state = 'expired_hold'
                """,
                (current, expires, stamp, request_id, route),
            )
            con.execute(
                "UPDATE messages SET status = 'Levetid forlenget – lagt tilbake i Base-kø', "
                "updated_at = ? WHERE message_uid = ?",
                (stamp, str(row["message_uid"])),
            )
            self._append_message_event(
                con, route, str(row["message_uid"]), "queue_renewed"
            )
            self._append_queue_event(
                con,
                route,
                request_id,
                "renewed",
                state="queued",
                attempts=int(row["attempts"]),
                detail=f"Levetid forlenget med {float(ttl_hours):g} time(r)",
            )
        return True

    def pause_gateway_request(self, request_id: str, route: str) -> bool:
        stamp = now_iso()
        current = time.time()
        with self._connection() as con:
            row = con.execute(
                "SELECT message_uid FROM gateway_outbox "
                "WHERE request_id = ? AND route = ? "
                "AND state IN ('queued', 'retry_wait')",
                (request_id, route),
            ).fetchone()
            if row is None:
                return False
            con.execute(
                """
                UPDATE gateway_outbox
                   SET state = 'paused', paused_at_epoch = ?, updated_at = ?
                 WHERE request_id = ? AND route = ?
                """,
                (current, stamp, request_id, route),
            )
            con.execute(
                "UPDATE messages SET status = 'Pauset i Base-kø', updated_at = ? "
                "WHERE message_uid = ?",
                (stamp, str(row["message_uid"])),
            )
            self._append_message_event(
                con, route, str(row["message_uid"]), "queue_paused"
            )
            attempts_row = con.execute(
                "SELECT attempts FROM gateway_outbox WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            self._append_queue_event(
                con,
                route,
                request_id,
                "paused",
                state="paused",
                attempts=int(attempts_row[0]) if attempts_row else 0,
                detail="Pauset av bruker",
            )
        return True

    def resume_gateway_request(self, request_id: str, route: str) -> bool:
        stamp = now_iso()
        current = time.time()
        with self._connection() as con:
            row = con.execute(
                "SELECT message_uid, paused_at_epoch FROM gateway_outbox "
                "WHERE request_id = ? AND route = ? AND state = 'paused'",
                (request_id, route),
            ).fetchone()
            if row is None:
                return False
            paused_at = float(row["paused_at_epoch"] or current)
            paused_duration = max(0.0, current - paused_at)
            con.execute(
                """
                UPDATE gateway_outbox
                   SET state = 'queued', next_attempt_epoch = ?,
                       expires_epoch = expires_epoch + ?, paused_at_epoch = NULL,
                       last_error = '', updated_at = ?
                 WHERE request_id = ? AND route = ? AND state = 'paused'
                """,
                (current, paused_duration, stamp, request_id, route),
            )
            con.execute(
                "UPDATE messages SET status = 'Gjenopptatt i Base-kø', updated_at = ? "
                "WHERE message_uid = ?",
                (stamp, str(row["message_uid"])),
            )
            self._append_message_event(
                con, route, str(row["message_uid"]), "queue_resumed"
            )
            attempts_row = con.execute(
                "SELECT attempts FROM gateway_outbox WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            self._append_queue_event(
                con,
                route,
                request_id,
                "resumed",
                state="queued",
                attempts=int(attempts_row[0]) if attempts_row else 0,
                detail="Gjenopptatt av bruker",
            )
        return True

    def cancel_gateway_request(self, request_id: str, route: str) -> bool:
        stamp = now_iso()
        with self._connection() as con:
            row = con.execute(
                "SELECT message_uid FROM gateway_outbox WHERE request_id = ? AND route = ? "
                "AND state NOT IN ('delivered', 'sent', 'failed')",
                (request_id, route),
            ).fetchone()
            if row is None:
                return False
            con.execute(
                "DELETE FROM gateway_outbox WHERE request_id = ? AND route = ?",
                (request_id, route),
            )
            con.execute(
                "DELETE FROM mesh_pending WHERE request_id = ? AND route = ?",
                (request_id, route),
            )
            con.execute(
                "UPDATE messages SET status = 'Avbrutt av bruker', updated_at = ? "
                "WHERE message_uid = ?",
                (stamp, str(row[0])),
            )
            self._append_queue_event(
                con,
                route,
                request_id,
                "cancelled",
                state="cancelled",
                detail="Avbrutt av bruker",
            )
        return True


class MeshBridge:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        mesh = config["meshtastic"]
        self.capability_view = runtime_capability_view(config)
        allowed, required_capability = network_capability_allowed(config, "mesh_local", mesh)
        if self.capability_view["enforced"] and not allowed:
            raise ValueError(
                "Hardware profile does not enable the configured Meshtastic radio capability: "
                + str(required_capability or "unmapped")
            )
        self.serial_port = str(mesh["serial_port"])
        self.api_host = str(mesh.get("api_host", "127.0.0.1"))
        self.api_port = int(mesh.get("api_port", 8766))
        self.channel_index = int(mesh.get("channel_index", 0))
        self.command_prefix = str(mesh.get("command_prefix", "@mesh "))
        self.network_name = str(mesh.get("network_name", "Meshtastic"))
        self.cursor_key = str(mesh.get("cursor_key", "waveshare_cursor"))
        self.forward_tag = str(mesh.get("forward_tag", "MT"))
        self.uid_prefix = str(mesh.get("uid_prefix", f"mt-{self.api_port}"))
        self.route_key = str(mesh.get("route_key", f"mesh-{self.api_port}"))
        self.structured_gateway = bool(mesh.get("structured_gateway", True))
        self.mesh_ack_timeout = float(mesh.get("ack_timeout_seconds", 75.0))
        self.gateway_address = int(mesh.get("gateway_address", config["address"]))
        self.max_control_bytes = int(config.get("max_text_bytes", 190))
        self.max_fragments = max(2, min(int(config.get("lc3_max_fragments", 4)), 4))
        self.gateway_retry_seconds = max(
            10.0, float(mesh.get("store_forward_retry_seconds", 300.0))
        )
        self.gateway_retry_max_seconds = max(
            self.gateway_retry_seconds,
            float(mesh.get("store_forward_retry_max_seconds", 3600.0)),
        )
        self.gateway_ttl_hours = max(
            0.1, float(mesh.get("store_forward_ttl_hours", 24.0))
        )
        self.gateway_max_pending = max(
            10, int(mesh.get("store_forward_max_pending", 500))
        )
        self.gateway_max_attempts = max(
            1, int(mesh.get("store_forward_max_attempts", 30))
        )
        self.message_sync_batch_size = max(
            1, min(int(mesh.get("message_sync_batch_size", 10)), 50)
        )
        self.position_history_sync_batch_size = max(
            1,
            min(
                int(
                    mesh.get(
                        "position_history_sync_batch_size",
                        self.message_sync_batch_size,
                    )
                ),
                50,
            ),
        )
        value = mesh.get("forward_inbound_to")
        self.forward_inbound_to = int(value) if value not in (None, "", 0) else None
        self.lorad_host = str(config.get("api_host", "127.0.0.1"))
        self.lorad_port = int(config.get("api_port", 8765))
        db_path = Path(config["database"])
        self.store = BridgeStore(db_path)
        self.catalog = NodeCatalog(db_path)
        self.position_store = PositionStore(db_path)
        self.interrupted_pending = self.store.interrupt_pending(self.route_key)
        recovered_gateway = self.store.recover_gateway_outbox(self.route_key)
        seeded_events = self.store.seed_message_events(self.route_key, self.network_name)
        if recovered_gateway:
            LOG.info("Gjenopptar %s gatewaymelding(er) i Base-kø", recovered_gateway)
        if seeded_events:
            LOG.info("Opprettet %s start-hendelser for meldingssynkronisering", seeded_events)
        self.interface: Any = None
        self.online = False
        self.last_error = ""
        self.last_rx = ""
        self.last_tx = ""
        self.local_num = 0
        self.local_id = ""
        self.local_name = "Meshtastic"
        self.local_short_name = ""
        self.stop_event = threading.Event()
        self.connection_lost = threading.Event()
        self.send_lock = threading.Lock()
        self.control_auth = ControlAuthenticator.from_environment(
            LC3ReplayStore(db_path)
        )
        if self.control_auth.enabled:
            LOG.info(
                "LC3-auth konfigurert (send=%s, required=%s, key_id=%s)",
                self.control_auth.send_authenticated,
                self.control_auth.require_authenticated,
                self.control_auth.key_id,
            )

        cursor = self.store.get_state_int(self.cursor_key)
        if cursor is None:
            cursor = self.store.max_message_id()
            self.store.set_state_int(self.cursor_key, cursor)
        self.ws_cursor = cursor

        pub.subscribe(self._on_receive_text, "meshtastic.receive.text")
        pub.subscribe(self._on_receive_position, "meshtastic.receive.position")
        pub.subscribe(self._on_connection, "meshtastic.connection.established")
        pub.subscribe(self._on_connection_lost, "meshtastic.connection.lost")
        pub.subscribe(self._on_node_updated, "meshtastic.node.updated")

    def start(self) -> None:
        threading.Thread(target=self._mesh_loop, name="meshtastic", daemon=True).start()
        threading.Thread(target=self._waveshare_poll_loop, name="ws-poll", daemon=True).start()
        threading.Thread(target=self._pending_loop, name="mesh-ack", daemon=True).start()

    def stop(self) -> None:
        self.stop_event.set()
        try:
            if self.interface is not None:
                self.interface.close()
        except Exception:
            LOG.exception("Kunne ikke lukke Meshtastic-grensesnittet")

    def _bind_receive_interface(self, interface: Any) -> None:
        self.interface = interface

    def _mesh_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.connection_lost.clear()
                LOG.info("Kobler til Meshtastic-radio på %s", self.serial_port)
                self.interface = ObservedSerialInterface(
                    devPath=self.serial_port,
                    _guto_bind_interface=self._bind_receive_interface,
                )
                self.online = True
                self.last_error = ""
                self._refresh_identity()
                self._sync_node_catalog()
                LOG.info(
                    "Meshtastic tilkoblet: %s (%s), node %s",
                    self.local_name,
                    self.local_id or "ukjent ID",
                    self.local_num,
                )
                while not self.stop_event.wait(0.5):
                    if self.connection_lost.is_set():
                        raise ConnectionError("Forbindelsen til Meshtastic-radioen ble brutt")
                    failure = transport_failure(self.interface)
                    if failure:
                        raise ConnectionError("Meshtastic-mottak utilgjengelig: " + failure)
            except Exception as exc:
                self.online = False
                self.last_error = f"{type(exc).__name__}: {exc}"
                LOG.exception("Meshtastic-feil; prøver igjen om 5 sekunder")
                try:
                    if self.interface is not None:
                        self.interface.close()
                except Exception:
                    pass
                self.interface = None
                self.stop_event.wait(5)

    def _refresh_identity(self) -> None:
        if self.interface is None:
            return
        try:
            info = getattr(self.interface, "myInfo", None)
            for attr in ("my_node_num", "myNodeNum"):
                value = getattr(info, attr, None)
                if value:
                    self.local_num = int(value)
                    break
            if not self.local_num:
                local_node = getattr(self.interface, "localNode", None)
                value = getattr(local_node, "nodeNum", None)
                if value:
                    self.local_num = int(value)
        except Exception:
            LOG.exception("Kunne ikke lese lokal node-ID")
        if self.local_num:
            self.local_id = f"!{self.local_num:08x}"
        try:
            node = self.interface.nodesByNum.get(self.local_num, {})
            user = node.get("user", {}) if isinstance(node, dict) else {}
            self.local_name = (
                user.get("longName")
                or user.get("shortName")
                or self.local_id
                or "Meshtastic"
            )
            self.local_short_name = str(user.get("shortName") or "")
            self.local_id = user.get("id") or self.local_id
        except Exception:
            pass

    def _on_connection(self, interface: Any, topic: Any = None) -> None:
        # Initial construction is attested by _mesh_loop; ignore stale callbacks.
        if interface is not self.interface:
            return
        self.online = True
        self.connection_lost.clear()
        self._refresh_identity()
        self._sync_node_catalog()

    def _on_connection_lost(self, interface: Any, topic: Any = None) -> None:
        if interface is not self.interface:
            return
        self.online = False
        self.connection_lost.set()

    def _on_node_updated(
        self,
        node: Any = None,
        interface: Any = None,
    ) -> None:
        """Handle both old and new Meshtastic node-update callback shapes.

        Recent Meshtastic releases publish both ``node`` and ``interface``.
        Listing ``interface`` explicitly is important because pypubsub validates
        subscriber argument names before dispatch and does not treat ``**kwargs``
        as an accepted optional topic argument.
        """
        if interface is not None and interface is not self.interface:
            return
        try:
            self._sync_node_catalog()
        except Exception:
            LOG.exception("Kunne ikke oppdatere varig nodekatalog")

    @staticmethod
    def _decoded_position(packet: dict[str, Any]) -> dict[str, Any] | None:
        """Return the decoded Meshtastic position mapping when present.

        Current Meshtastic releases publish ``decoded.position`` on the
        ``meshtastic.receive.position`` topic.  Accepting a coordinate mapping
        directly in ``decoded`` as a conservative fallback keeps synthetic
        tests and older packet shapes useful without decoding raw protobuf
        payloads in LoRa Chat.
        """
        decoded = packet.get("decoded")
        if not isinstance(decoded, dict):
            return None
        position = decoded.get("position")
        if isinstance(position, dict):
            return position
        coordinate_names = {
            "latitudeI", "longitudeI", "latitude_i", "longitude_i",
            "latitude", "longitude",
        }
        if any(name in decoded for name in coordinate_names):
            return decoded
        return None

    def _on_receive_position(
        self,
        packet: dict[str, Any],
        interface: Any = None,
    ) -> None:
        """Validate and persist a decoded Meshtastic position packet.

        This callback atomically appends a deduplicated history point and
        updates the local latest-position snapshot when the observation is
        newer or better.  It deliberately does not transmit from the receive
        callback; Base-to-Mobile synchronization remains a separate bounded
        control exchange.
        """
        if interface is not None and interface is not self.interface:
            return
        if interface is not None:
            self.interface = interface
        try:
            if not isinstance(packet, dict):
                return
            position = self._decoded_position(packet)
            if position is None:
                LOG.debug("Ignorerer posisjonshendelse uten dekodet posisjon")
                return

            source_num_raw = packet.get("from")
            source_num = int(source_num_raw) if source_num_raw not in (None, "") else 0
            if self.local_num and source_num == self.local_num:
                return
            source_id = str(packet.get("fromId") or "").strip()
            if not source_id and source_num:
                source_id = f"!{source_num:08x}"
            if not source_id:
                LOG.warning("Avviser Meshtastic-posisjon uten avsender-ID")
                return

            result = self.position_store.upsert_latest(
                self.route_key,
                source_id,
                position,
                num=source_num if source_num else None,
                packet_rx_epoch=packet.get("rxTime"),
                source="meshtastic.receive.position",
                packet_id=packet.get("id") or "",
                channel=packet.get("channel"),
                rx_rssi=packet.get("rxRssi"),
                rx_snr=packet.get("rxSnr"),
            )
            if result in {"created", "updated"}:
                self.last_rx = now_iso()
                self._sync_node_catalog()
                LOG.info(
                    "Meshtastic-posisjon %s for %s på %s",
                    "lagret" if result == "created" else "oppdatert",
                    source_id,
                    self.route_key,
                )
            elif result == "suspicious":
                LOG.warning(
                    "Avviser mistenkelig Meshtastic-posisjon fra %s "
                    "(presisjonsmidtpunkt-signatur)",
                    source_id,
                )
            elif result == "invalid":
                LOG.warning("Avviser ugyldig Meshtastic-posisjon fra %s", source_id)
        except Exception as exc:
            self.last_error = f"Posisjonsfeil: {type(exc).__name__}: {exc}"
            LOG.exception("Kunne ikke behandle Meshtastic-posisjon")

    @staticmethod
    def _decoded_text(packet: dict[str, Any]) -> str:
        decoded = packet.get("decoded", {})
        text = decoded.get("text")
        if isinstance(text, str):
            return text
        payload = decoded.get("payload")
        if isinstance(payload, bytes):
            return payload.decode("utf-8", errors="replace")
        if isinstance(payload, str):
            return payload
        return ""

    @staticmethod
    def _clean_node_name(value: Any) -> str:
        return " ".join(str(value or "").split())

    @classmethod
    def _unambiguous_node_label(
        cls,
        node_num: int,
        fallback_id: str,
        nodes: list[dict[str, Any]],
    ) -> str:
        canonical_id = canonical_meshtastic_id(fallback_id, node_num=node_num)
        target: dict[str, Any] | None = None
        for node in nodes:
            try:
                candidate_num = int(node.get("num", -1))
            except (TypeError, ValueError):
                candidate_num = -1
            if candidate_num == node_num:
                target = node
                break
        if target is None:
            return canonical_id
        long_name = cls._clean_node_name(target.get("long_name"))
        short_name = cls._clean_node_name(target.get("short_name"))
        target_id = canonical_meshtastic_id(
            target.get("id") or target.get("node_id") or canonical_id,
            node_num=node_num,
        )
        ambiguous = False
        if long_name:
            for candidate in nodes:
                try:
                    candidate_num = int(candidate.get("num", -1))
                except (TypeError, ValueError):
                    candidate_num = -1
                candidate_name = cls._clean_node_name(
                    candidate.get("long_name")
                )
                if (
                    candidate_num != node_num
                    and candidate_name
                    and candidate_name.casefold() == long_name.casefold()
                ):
                    ambiguous = True
                    break
        if ambiguous:
            if short_name and short_name.casefold() != long_name.casefold():
                return f"{long_name} / {short_name} ({target_id})"
            return f"{long_name} ({target_id})"
        return long_name or short_name or target_id

    def _node_label(self, node_num: int, fallback_id: str = "") -> str:
        canonical_fallback = canonical_meshtastic_id(
            fallback_id, node_num=node_num
        )
        try:
            if self.interface is not None:
                nodes: list[dict[str, Any]] = []
                for candidate_num, candidate in self.interface.nodesByNum.items():
                    if not isinstance(candidate, dict):
                        continue
                    user = candidate.get("user", {})
                    nodes.append(
                        {
                            "num": int(candidate_num),
                            "id": user.get("id", f"!{int(candidate_num):08x}"),
                            "long_name": user.get("longName", ""),
                            "short_name": user.get("shortName", ""),
                        }
                    )
                if nodes:
                    return self._unambiguous_node_label(
                        node_num, canonical_fallback, nodes
                    )
        except Exception:
            pass
        catalog_nodes = self.catalog.list_nodes(self.route_key)
        if catalog_nodes:
            return self._unambiguous_node_label(
                node_num, canonical_fallback, catalog_nodes
            )
        return canonical_fallback

    def _live_nodes(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        if self.interface is None:
            return result
        try:
            for node_num, node in self.interface.nodesByNum.items():
                user = node.get("user", {}) if isinstance(node, dict) else {}
                result.append(
                    {
                        "num": int(node_num),
                        "id": user.get("id", f"!{int(node_num):08x}"),
                        "long_name": user.get("longName", ""),
                        "short_name": user.get("shortName", ""),
                        "last_heard": node.get("lastHeard") if isinstance(node, dict) else None,
                        "snr": node.get("snr") if isinstance(node, dict) else None,
                        "last_updated": now_iso(),
                    }
                )
        except Exception:
            LOG.exception("Kunne ikke lese nodelisten")
        return result

    def _sync_node_catalog(self) -> None:
        nodes = self._live_nodes()
        if nodes:
            self.catalog.upsert_many(self.route_key, nodes, source=self.network_name)

    def nodes(self, since_revision: int = 0) -> list[dict[str, Any]]:
        self._sync_node_catalog()
        rows = self.catalog.list_nodes(self.route_key, since_revision)
        result: list[dict[str, Any]] = []
        for row in rows:
            result.append(
                {
                    "num": int(row["num"]),
                    "id": str(row["node_id"]),
                    "long_name": str(row.get("long_name", "")),
                    "short_name": str(row.get("short_name", "")),
                    "last_heard": row.get("last_heard"),
                    "snr": row.get("snr"),
                    "revision": int(row.get("revision", 0)),
                    "last_updated": str(row.get("last_updated", "")),
                }
            )
        return result

    def positions(self, since_revision: int = 0) -> list[dict[str, Any]]:
        """Return latest positions for this bridge route only."""
        return self.position_store.list_latest(
            self.route_key,
            since_revision=since_revision,
        )

    def position(self, node_id: Any) -> dict[str, Any] | None:
        """Return one latest position for this bridge route."""
        return self.position_store.get_latest(self.route_key, node_id)

    def position_status(self) -> dict[str, Any]:
        """Return route-scoped position metadata without coordinates."""
        return self.position_store.aggregate_status(self.route_key)

    def position_history(
        self,
        *,
        since_sequence: int = 0,
        limit: int = 50,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Return one bounded history batch for this bridge route."""
        return self.position_store.history_since(
            self.route_key,
            since_sequence,
            limit,
        )

    def _client_protocol_key(self, waveshare_source: int) -> str:
        return f"client_protocol:{self.route_key}:{int(waveshare_source)}"

    def _remember_client_protocol(self, waveshare_source: int, protocol_name: str) -> None:
        value = "LC3" if str(protocol_name).upper() == "LC3" else "LC2"
        self.store.set_state(self._client_protocol_key(waveshare_source), value)

    def _client_protocol(self, waveshare_source: int) -> str:
        # Default to LC2 until the peer has explicitly sent an LC3 request.
        # This keeps Base-first upgrades safe for a still-running beta3a Mobile.
        return self.store.get_state(self._client_protocol_key(waveshare_source)) or "LC2"

    def _send_waveshare_control(self, destination: int, text: str) -> None:
        wire_text = self.control_auth.encode_outbound(text)
        frames = fragment_frame(
            wire_text,
            max_bytes=self.max_control_bytes,
            max_fragments=self.max_fragments,
        )
        policy = control_transport_policy(text, destination)
        for frame in frames:
            request = {
                "command": "send",
                "destination": int(destination),
                "text": frame,
            }
            request.update(policy)
            json_api_call(self.lorad_host, self.lorad_port, request)

    @staticmethod
    def _friendly_routing_reason(reason: str) -> str:
        values = {
            "NO_RESPONSE": "ingen svar fra mottakernoden",
            "NO_ROUTE": "ingen kjent rute",
            "MAX_RETRANSMIT": "maksimalt antall nye forsøk brukt",
            "DUTY_CYCLE_LIMIT": "sendebegrensning/duty cycle",
            "BAD_REQUEST": "ugyldig forespørsel",
            "NOT_AUTHORIZED": "ikke autorisert",
            "PKI_FAILED": "kryptering eller nøkkelkontroll feilet",
            "UKJENT_SVAR": "ukjent svar fra radioen",
        }
        return values.get(reason, reason.replace("_", " ").lower())

    @staticmethod
    def _gateway_retryable(reason: str) -> bool:
        return reason in {
            "NO_RESPONSE",
            "NO_ROUTE",
            "MAX_RETRANSMIT",
            "DUTY_CYCLE_LIMIT",
            "UKJENT_SVAR",
            "TIMEOUT",
            "RADIO_OFFLINE",
            "BRIDGE_RESTART",
        }

    def _gateway_retry_delay(self, attempts: int) -> float:
        """Exponential retry delay capped at the configured maximum."""
        exponent = max(0, min(int(attempts) - 1, 8))
        return min(
            self.gateway_retry_seconds * (2 ** exponent),
            self.gateway_retry_max_seconds,
        )

    @staticmethod
    def _queue_legacy(row: dict[str, Any] | None) -> bool:
        return bool(row and str(row.get("protocol", "LC3")).upper() == "LC2")

    def _notify_queue_state(self, row: dict[str, Any], detail: str = "") -> None:
        source = row.get("waveshare_source")
        if source in (None, "") or self._queue_legacy(row):
            return
        try:
            self._send_waveshare_control(
                int(source),
                encode_gateway_queued(
                    str(row["request_id"]),
                    self.route_key,
                    str(row.get("state", "queued")),
                    int(row.get("attempts", 0)),
                    row.get("next_attempt_epoch"),
                    detail or str(row.get("last_error", "")),
                ),
            )
        except Exception:
            LOG.exception("Kunne ikke sende Base-køstatus til Mobile")

    def _notify_gateway_final(
        self,
        row: dict[str, Any],
        *,
        ok: bool,
        packet_id: str = "",
        reason: str = "",
    ) -> None:
        source = row.get("waveshare_source")
        request_id = str(row.get("request_id") or "")
        if source in (None, "") or not request_id:
            return
        legacy = self._queue_legacy(row)
        destination = str(row.get("destination", "^all"))
        try:
            if ok:
                control = encode_gateway_delivered(
                    request_id,
                    self.route_key,
                    packet_id,
                    destination,
                    legacy=legacy,
                )
            else:
                control = encode_gateway_nak(
                    request_id,
                    self.route_key,
                    packet_id,
                    destination,
                    reason,
                    legacy=legacy,
                )
            self._send_waveshare_control(int(source), control)
        except Exception:
            LOG.exception("Kunne ikke sende sluttstatus for Base-kø")

    def _handle_gateway_failure(
        self,
        pending: dict[str, Any],
        *,
        reason_code: str,
        friendly: str,
    ) -> None:
        request_id = str(pending.get("request_id") or "")
        queue_row = self.store.gateway_request(request_id) if request_id else None
        message_uid = str(pending["message_uid"])
        if queue_row is None:
            self.store.update_message_status(
                message_uid,
                f"Ikke bekreftet: {friendly}",
                route=self.route_key,
            )
            source = pending.get("waveshare_source")
            if source not in (None, "") and request_id:
                try:
                    self._send_waveshare_control(
                        int(source),
                        encode_gateway_nak(
                            request_id,
                            self.route_key,
                            str(pending.get("packet_id", "")),
                            str(pending["destination"]),
                            friendly,
                            legacy=False,
                        ),
                    )
                except Exception:
                    LOG.exception("Kunne ikke sende Meshtastic-feil til Mobile")
            return

        attempts = int(queue_row.get("attempts", 0))
        expires = float(queue_row.get("expires_epoch", 0))
        can_retry = (
            self._gateway_retryable(reason_code)
            and attempts < self.gateway_max_attempts
            and expires > time.time()
        )
        if can_retry:
            status = f"Base-kø: nytt forsøk senere ({friendly})"
            updated = self.store.schedule_gateway_retry(
                request_id,
                delay_seconds=self._gateway_retry_delay(attempts),
                error=friendly,
                status=status,
            )
            if updated is not None:
                self._notify_queue_state(updated, friendly)
            LOG.warning(
                "Gatewayforespørsel %s beholdes i Base-kø etter %s",
                request_id,
                friendly,
            )
            return

        failed = self.store.complete_gateway_request(
            request_id,
            state="failed",
            status=f"Ikke levert: {friendly}",
            error=friendly,
        )
        if failed is not None:
            self._notify_gateway_final(
                failed,
                ok=False,
                packet_id=str(pending.get("packet_id", "")),
                reason=friendly,
            )
        LOG.warning("Gatewayforespørsel %s feilet endelig: %s", request_id, friendly)

    def _handle_mesh_response(self, context: dict[str, Any], packet: dict[str, Any]) -> None:
        packet_id = str(context.get("packet_id", ""))
        if not packet_id:
            return
        pending = self.store.pop_pending(packet_id, self.route_key)
        if pending is None:
            return
        pending["packet_id"] = packet_id
        ok, reason = parse_routing_result(packet)
        message_uid = str(pending["message_uid"])
        request_id = str(pending.get("request_id") or "")
        queue_row = self.store.gateway_request(request_id) if request_id else None
        if ok:
            if queue_row is not None:
                completed = self.store.complete_gateway_request(
                    request_id,
                    state="delivered",
                    status="Bekreftet av mottakernode",
                )
                if completed is not None:
                    self._notify_gateway_final(completed, ok=True, packet_id=packet_id)
            else:
                self.store.update_message_status(
                    message_uid,
                    "Bekreftet av mottakernode",
                    route=self.route_key,
                )
                source = pending.get("waveshare_source")
                if source not in (None, "") and request_id:
                    self._send_waveshare_control(
                        int(source),
                        encode_gateway_delivered(
                            request_id,
                            self.route_key,
                            packet_id,
                            str(pending["destination"]),
                        ),
                    )
            LOG.info("Meshtastic ACK for pakke %s", packet_id)
            return

        friendly = self._friendly_routing_reason(reason)
        self._handle_gateway_failure(
            pending,
            reason_code=reason,
            friendly=friendly,
        )
        LOG.warning("Meshtastic NAK for pakke %s: %s", packet_id, friendly)

    def _queue_gateway_message(
        self,
        *,
        request_id: str,
        destination: str | int,
        channel: int,
        text: str,
        source_label: str,
        waveshare_source: int | None,
        protocol_name: str,
        priority: int = 100,
    ) -> tuple[dict[str, Any], bool]:
        row, created = self.store.enqueue_gateway_request(
            request_id=request_id,
            route=self.route_key,
            waveshare_source=waveshare_source,
            destination=destination,
            channel=channel,
            text=text,
            source_label=source_label,
            protocol=protocol_name,
            ttl_hours=self.gateway_ttl_hours,
            priority=priority,
            max_pending=self.gateway_max_pending,
        )
        if created:
            destination_num = destination_to_num(destination)
            self.store.add_meshtastic(
                message_uid=str(row["message_uid"]),
                direction="sent",
                source=self.local_num,
                destination=destination_num,
                source_label=source_label,
                destination_label=(
                    "Broadcast"
                    if destination_num == BROADCAST_NUM
                    else self._node_label(destination_num)
                ),
                text=text,
                packet_rssi=None,
                snr=None,
                channel=channel,
                status="Lagret i Base-kø",
                network=self.network_name,
                route=self.route_key,
                gateway_request_id=request_id,
            )
        self._notify_queue_state(row, "lagret varig på Base")
        return row, created

    def _process_gateway_outbox(self) -> None:
        for expired in self.store.expire_gateway_requests(self.route_key):
            self._notify_queue_state(
                expired,
                "levetid utløpt – beholdt i Base-kø",
            )

        item = self.store.next_gateway_due(self.route_key)
        if item is None:
            return
        request_id = str(item["request_id"])
        if int(item.get("attempts", 0)) >= self.gateway_max_attempts:
            failed = self.store.complete_gateway_request(
                request_id,
                state="failed",
                status="Ikke levert: maksimalt antall Base-forsøk brukt",
                error="maksimalt antall Base-forsøk brukt",
            )
            if failed is not None:
                self._notify_gateway_final(
                    failed,
                    ok=False,
                    reason="maksimalt antall Base-forsøk brukt",
                )
            return
        if not self.online or self.interface is None:
            updated = self.store.schedule_gateway_retry(
                request_id,
                delay_seconds=self.gateway_retry_seconds,
                error="Meshtastic-radioen er frakoblet",
                status="Base-kø: venter på Meshtastic-radio",
            )
            if updated is not None:
                self._notify_queue_state(updated, "Meshtastic-radioen er frakoblet")
            return

        attempts = self.store.mark_gateway_sending(request_id)
        destination = str(item["destination"])
        try:
            packet_id = self.send_text(
                str(item["text"]),
                destination,
                int(item["channel"]),
                source_label=str(item["source_label"]),
                gateway_request_id=request_id,
                gateway_source=(
                    int(item["waveshare_source"])
                    if item.get("waveshare_source") not in (None, "")
                    else None
                ),
                logical_message_uid=str(item["message_uid"]),
                attempts=attempts,
            )
            direct = destination_to_num(destination) != BROADCAST_NUM
            current = self.store.gateway_request(request_id)
            # A synthetic/test interface or a very fast radio can invoke the
            # ACK callback before send_text() returns.  Do not overwrite an
            # already delivered, failed or rescheduled queue state.
            if direct and current is not None and current.get("state") == "sending":
                self.store.mark_gateway_waiting(
                    request_id, packet_id, "Venter på mottakernode"
                )
            elif not direct and current is not None and current.get("state") == "sending":
                self.store.complete_gateway_request(
                    request_id,
                    state="sent",
                    status="Overlevert til Meshtastic-radio",
                )
            source = item.get("waveshare_source")
            if source not in (None, ""):
                self._send_waveshare_control(
                    int(source),
                    encode_gateway_ack(
                        request_id,
                        self.route_key,
                        packet_id,
                        destination,
                        legacy=self._queue_legacy(item),
                    ),
                )
        except Exception as exc:
            friendly = f"{type(exc).__name__}: {exc}"
            updated = self.store.schedule_gateway_retry(
                request_id,
                delay_seconds=self._gateway_retry_delay(attempts),
                error=friendly,
                status="Base-kø: sendefeil – prøver senere",
            )
            if updated is not None:
                self._notify_queue_state(updated, friendly)
            LOG.exception("Gatewayforespørsel %s beholdes etter sendefeil", request_id)

    def _pending_loop(self) -> None:
        while not self.stop_event.wait(1.0):
            try:
                # A queued request is already reset to 'queued' on service start.
                remaining: list[dict[str, Any]] = []
                for row in self.interrupted_pending:
                    request_id = str(row.get("request_id") or "")
                    if request_id and self.store.gateway_request(request_id) is not None:
                        continue
                    source = row.get("waveshare_source")
                    if source in (None, "") or not request_id:
                        self.store.update_message_status(
                            str(row["message_uid"]),
                            "Ikke bekreftet: brotjenesten startet på nytt",
                            route=self.route_key,
                        )
                        continue
                    try:
                        self._send_waveshare_control(
                            int(source),
                            encode_gateway_nak(
                                request_id,
                                self.route_key,
                                str(row["packet_id"]),
                                str(row["destination"]),
                                "brotjenesten startet på nytt før kvittering",
                            ),
                        )
                    except Exception:
                        remaining.append(row)
                self.interrupted_pending = remaining

                for row in self.store.expire_pending(self.route_key):
                    row["packet_id"] = str(row.get("packet_id", ""))
                    self._handle_gateway_failure(
                        row,
                        reason_code="TIMEOUT",
                        friendly="tidsavbrudd uten kvittering fra mottakernoden",
                    )

                self._process_gateway_outbox()
            except Exception:
                LOG.exception(
                    "Feil i Meshtastic pending/kø-loop; prøver igjen om ett sekund"
                )

    def _handle_gateway_control(self, row: dict[str, Any]) -> bool:
        source = int(row.get("source", 0))
        raw_text = str(row.get("text", ""))
        control = parse_control(raw_text)
        if control and control.get("command") == "FRAGMENT":
            try:
                assembled = self.store.add_control_fragment(
                    route=self.route_key,
                    waveshare_source=source,
                    control=control,
                    max_fragments=self.max_fragments,
                )
            except Exception as exc:
                LOG.warning("Avviser ugyldig LC3-fragment fra %s: %s", source, exc)
                return True
            if assembled is None:
                return True
            raw_text = assembled
        try:
            raw_text, _verified = self.control_auth.decode_inbound(
                raw_text,
                live=True,
            )
        except ValueError as exc:
            if raw_text.startswith("~L3|"):
                LOG.warning("Avviser LC3-kontroll fra %s: %s", source, exc)
                return True
            return False
        control = parse_control(raw_text)
        if not control or control.get("route") != self.route_key:
            return False
        command = str(control.get("command", ""))
        request_id = str(control.get("request_id", ""))
        protocol_name = str(control.get("protocol", "LC3"))
        legacy = protocol_name == "LC2"
        if source:
            self._remember_client_protocol(source, protocol_name)
        try:
            if command == "SEND":
                self._queue_gateway_message(
                    request_id=request_id,
                    destination=control.get("destination", "^all"),
                    channel=int(control.get("channel", self.channel_index)),
                    text=str(control["text"]),
                    source_label=f"Waveshare {source}",
                    waveshare_source=source,
                    protocol_name=protocol_name,
                )
                return True
            if command == "NREQ":
                since = int(control.get("since_revision", 0))
                nodes = self.nodes(since)
                for node in nodes:
                    self._send_waveshare_control(
                        source,
                        encode_node(
                            request_id,
                            self.route_key,
                            int(node["num"]),
                            str(node["id"]),
                            str(node.get("short_name", "")),
                            str(node.get("long_name", "")),
                            revision=int(node.get("revision", 0)),
                            last_heard=node.get("last_heard"),
                            snr=node.get("snr"),
                            legacy=legacy,
                        ),
                    )
                self._send_waveshare_control(
                    source,
                    encode_nodes_done(
                        request_id,
                        self.route_key,
                        len(nodes),
                        total_count=self.catalog.count(self.route_key),
                        revision=self.catalog.current_revision(self.route_key),
                        legacy=legacy,
                    ),
                )
                return True
            if command == "IREQ":
                self._refresh_identity()
                self._sync_node_catalog()
                self._send_waveshare_control(
                    source,
                    encode_info(
                        request_id,
                        self.route_key,
                        APP_VERSION,
                        self.network_name,
                        self.online,
                        self.catalog.count(self.route_key),
                        legacy=legacy,
                    ),
                )
                if not legacy and self.local_id:
                    self._send_waveshare_control(
                        source,
                        encode_gateway_identity(
                            request_id,
                            self.route_key,
                            self.local_id,
                            self.local_name,
                            self.local_short_name,
                        ),
                    )
                return True
            if command == "PREQ":
                since = int(control.get("since_revision", 0))
                positions = self.position_store.list_latest(
                    self.route_key, since_revision=since
                )
                for position in positions:
                    self._send_waveshare_control(
                        source,
                        encode_position_sync(
                            request_id,
                            self.route_key,
                            int(position.get("revision", 0)),
                            position,
                        ),
                    )
                self._send_waveshare_control(
                    source,
                    encode_positions_done(
                        request_id,
                        self.route_key,
                        self.position_store.current_revision(self.route_key),
                        len(positions),
                    ),
                )
                return True
            if command == "HREQ":
                since = int(control.get("since_sequence", 0))
                limit = int(
                    control.get(
                        "limit",
                        self.position_history_sync_batch_size,
                    )
                )
                positions, more = self.position_store.history_since(
                    self.route_key,
                    since,
                    limit,
                )
                last_sequence = since
                for position in positions:
                    last_sequence = int(position.get("sequence", last_sequence))
                    self._send_waveshare_control(
                        source,
                        encode_position_history_sync(
                            request_id,
                            self.route_key,
                            last_sequence,
                            position,
                        ),
                    )
                if not positions and not more:
                    last_sequence = self.position_store.current_history_sequence(
                        self.route_key
                    )
                self._send_waveshare_control(
                    source,
                    encode_position_history_done(
                        request_id,
                        self.route_key,
                        last_sequence,
                        len(positions),
                        more,
                    ),
                )
                return True
            if command == "MREQ":
                events, more = self.store.message_events_since(
                    self.route_key,
                    int(control.get("since_sequence", 0)),
                    int(control.get("limit", self.message_sync_batch_size)),
                )
                last_sequence = int(control.get("since_sequence", 0))
                for event in events:
                    last_sequence = int(event["sequence"])
                    self._send_waveshare_control(
                        source,
                        encode_message_sync(
                            request_id,
                            self.route_key,
                            last_sequence,
                            str(event["event_type"]),
                            dict(event["payload"]),
                        ),
                    )
                self._send_waveshare_control(
                    source,
                    encode_message_done(
                        request_id,
                        self.route_key,
                        last_sequence,
                        len(events),
                        more,
                    ),
                )
                return True
        except Exception as exc:
            LOG.exception("Strukturert gatewaykommando feilet")
            if source and request_id:
                try:
                    self._send_waveshare_control(
                        source,
                        encode_gateway_error(
                            request_id,
                            self.route_key,
                            f"{type(exc).__name__}: {exc}",
                            legacy=legacy,
                        ),
                    )
                except Exception:
                    LOG.exception("Kunne ikke sende gateway-feilmelding")
            return True
        return False

    def _on_receive_text(self, packet: dict[str, Any], interface: Any = None) -> None:
        if interface is not None and interface is not self.interface:
            return
        try:
            text = self._decoded_text(packet).strip()
            if not text:
                return
            source = int(packet.get("from", 0))
            if self.local_num and source == self.local_num:
                return
            destination = int(packet.get("to", BROADCAST_NUM))
            source_id = str(packet.get("fromId", ""))
            source_label = self._node_label(source, source_id)
            destination_label = (
                "Broadcast"
                if destination == BROADCAST_NUM
                else self._node_label(destination, str(packet.get("toId", "")))
            )
            packet_id = packet.get("id") or uuid.uuid4().hex[:12]
            rssi_raw = packet.get("rxRssi")
            snr_raw = packet.get("rxSnr")
            channel = int(packet.get("channel", self.channel_index))
            rssi = int(rssi_raw) if rssi_raw is not None else None
            snr = float(snr_raw) if snr_raw is not None else None
            self.store.add_meshtastic(
                message_uid=f"{self.uid_prefix}-{packet_id}",
                direction="received",
                source=source,
                destination=destination,
                source_label=source_label,
                destination_label=destination_label,
                text=text,
                packet_rssi=rssi,
                snr=snr,
                channel=channel,
                status=f"Mottatt ({self.network_name})",
                network=self.network_name,
                route=self.route_key,
            )
            self._sync_node_catalog()
            self.last_rx = now_iso()
            LOG.info(
                "Meshtastic mottatt fra %s (%s UTF-8-byte)",
                source_label, len(text.encode("utf-8")),
            )

            if self.forward_inbound_to is not None:
                forwarded = None
                if self.structured_gateway:
                    peer_protocol = self._client_protocol(self.forward_inbound_to)
                    forwarded = encode_mesh_in(
                        self.route_key,
                        source_id or f"!{source:08x}",
                        source_label,
                        "^all" if destination == BROADCAST_NUM else destination,
                        channel,
                        text,
                        message_uid=f"{self.uid_prefix}-{packet_id}",
                        legacy=peer_protocol != "LC3",
                    )
                if forwarded is None:
                    forwarded = f"[{self.forward_tag} {source_label}] {text}"
                self._send_waveshare_control(self.forward_inbound_to, forwarded)
                LOG.info(
                    "Videresendt Meshtastic-melding til Waveshare-adresse %s",
                    self.forward_inbound_to,
                )
        except Exception as exc:
            self.last_error = f"Mottaksfeil: {type(exc).__name__}: {exc}"
            LOG.exception("Kunne ikke behandle Meshtastic-melding")

    def send_text(
        self,
        text: str,
        destination: str | int = "^all",
        channel_index: int | None = None,
        source_label: str | None = None,
        gateway_request_id: str = "",
        gateway_source: int | None = None,
        logical_message_uid: str = "",
        attempts: int = 1,
    ) -> str:
        text = text.strip()
        if not text:
            raise ValueError("Meldingen er tom")
        if len(text.encode("utf-8")) > 220:
            raise ValueError("Meshtastic-meldingen er for lang; maks 220 UTF-8-byte")
        if not self.online or transport_failure(self.interface):
            raise RuntimeError("Meshtastic-radioen er ikke tilkoblet")
        channel = self.channel_index if channel_index is None else int(channel_index)
        destination_num = destination_to_num(destination)
        direct = destination_num != BROADCAST_NUM
        context: dict[str, Any] = {"packet_id": "", "early_response": None}
        context_lock = threading.Lock()

        def onAckNak(packet: dict[str, Any]) -> None:
            # Meshtastic normally invokes this asynchronously. Keep the code
            # correct even if a very fast response arrives before sendText()
            # has returned the packet ID and the pending row has been stored.
            with context_lock:
                if not context.get("packet_id"):
                    context["early_response"] = packet
                    return
            self._handle_mesh_response(context, packet)

        with self.send_lock:
            packet = self.interface.sendText(
                text,
                destinationId=destination,
                wantAck=direct,
                onResponse=onAckNak if direct else None,
                channelIndex=channel,
            )
        packet_id = str(getattr(packet, "id", None) or uuid.uuid4().hex[:12])
        # Publish the packet ID to callbacks only after the pending row exists.
        # Until then the callback buffers its response under context_lock.
        destination_label = (
            "Broadcast" if not direct else self._node_label(destination_num)
        )
        message_uid = logical_message_uid or f"{self.uid_prefix}-{packet_id}"
        status = "Venter på mottakernode" if direct else "Overlevert til Meshtastic-radio"
        self.store.add_meshtastic(
            message_uid=message_uid,
            direction="sent",
            source=self.local_num,
            destination=destination_num,
            source_label=source_label or self.local_name,
            destination_label=destination_label,
            text=text,
            packet_rssi=None,
            snr=None,
            channel=channel,
            status=status,
            network=self.network_name,
            route=self.route_key,
            gateway_request_id=gateway_request_id,
            attempts=attempts,
        )
        early_response: dict[str, Any] | None = None
        if direct:
            self.store.add_pending(
                packet_id=packet_id,
                message_uid=message_uid,
                route=self.route_key,
                request_id=gateway_request_id,
                waveshare_source=gateway_source,
                destination=destination,
                deadline_epoch=time.time() + self.mesh_ack_timeout,
            )
            with context_lock:
                context["packet_id"] = packet_id
                early = context.get("early_response")
                if isinstance(early, dict):
                    early_response = early
                    context["early_response"] = None
        else:
            with context_lock:
                context["packet_id"] = packet_id
        if early_response is not None:
            self._handle_mesh_response(context, early_response)
        self.last_tx = now_iso()
        LOG.info(
            "Meshtastic sendt til %s (%s UTF-8-byte)",
            destination_label, len(text.encode("utf-8")),
        )
        return packet_id

    def _waveshare_poll_loop(self) -> None:
        while not self.stop_event.wait(1.0):
            try:
                row = self.store.next_received_waveshare(self.ws_cursor)
                if row is None:
                    continue
                row_id = int(row["id"])
                text = str(row.get("text", ""))
                destination = int(row.get("destination", 0))
                if destination == self.gateway_address:
                    handled = self._handle_gateway_control(row)
                    if not handled and text.startswith(self.command_prefix):
                        body = text[len(self.command_prefix) :].strip()
                        if body:
                            source = int(row.get("source", 0))
                            self.send_text(
                                f"[WS-{source}] {body}",
                                source_label=f"Waveshare {source}",
                            )
                self.ws_cursor = row_id
                self.store.set_state_int(self.cursor_key, self.ws_cursor)
            except Exception as exc:
                self.last_error = f"Gateway-feil: {type(exc).__name__}: {exc}"
                LOG.exception("Kunne ikke behandle Waveshare→Meshtastic")
                self.stop_event.wait(3)

    def status(self) -> dict[str, Any]:
        self._refresh_identity()
        self._sync_node_catalog()
        gateway_counts = self.store.gateway_counts(self.route_key)
        receive_health = receive_health_snapshot(self.interface, self.online)
        return {
            "online": self.online and receive_health["state"] != "DISCONNECTED",
            "receive_health": receive_health,
            "serial_port": self.serial_port,
            "network_name": self.network_name,
            "cursor_key": self.cursor_key,
            "local_num": self.local_num,
            "local_id": self.local_id,
            "local_name": self.local_name,
            "local_short_name": self.local_short_name,
            "channel_index": self.channel_index,
            "node_count": self.catalog.count(self.route_key),
            "node_revision": self.catalog.current_revision(self.route_key),
            "last_rx": self.last_rx,
            "last_tx": self.last_tx,
            "last_error": self.last_error,
            "forward_inbound_to": self.forward_inbound_to,
            "command_prefix": self.command_prefix,
            "route_key": self.route_key,
            "service_version": APP_VERSION,
            "structured_gateway": self.structured_gateway,
            "mesh_ack_timeout_seconds": self.mesh_ack_timeout,
            "lc3_max_fragments": self.max_fragments,
            "gateway_store_forward_pending": gateway_counts.get("pending", 0),
            "gateway_store_forward_counts": gateway_counts,
            "gateway_store_forward_retry_seconds": self.gateway_retry_seconds,
            "gateway_store_forward_retry_max_seconds": self.gateway_retry_max_seconds,
            "gateway_store_forward_ttl_hours": self.gateway_ttl_hours,
            "gateway_store_forward_max_pending": self.gateway_max_pending,
            "gateway_store_forward_max_attempts": self.gateway_max_attempts,
            "message_sync_batch_size": self.message_sync_batch_size,
            "position_history_sync_batch_size": (
                self.position_history_sync_batch_size
            ),
            "position_status": self.position_status(),
            "protocol": "LC3",
            "capability_policy": dict(self.capability_view),
        }


class ApiHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        bridge: MeshBridge = self.server.bridge  # type: ignore[attr-defined]
        try:
            request = json.loads(self.rfile.readline(1024 * 1024).decode("utf-8"))
            command = request.get("command")
            if command == "status":
                response = {"ok": True, "status": bridge.status()}
            elif command == "nodes":
                since = int(request.get("since_revision", 0))
                response = {
                    "ok": True,
                    "nodes": bridge.nodes(since),
                    "revision": bridge.catalog.current_revision(bridge.route_key),
                    "total_count": bridge.catalog.count(bridge.route_key),
                }
            elif command == "positions":
                since = int(request.get("since_revision", 0))
                response = {
                    "ok": True,
                    "positions": bridge.positions(since),
                    "revision": bridge.position_store.current_revision(
                        bridge.route_key
                    ),
                    "total_count": bridge.position_store.count(bridge.route_key),
                    "route_key": bridge.route_key,
                }
            elif command == "position":
                node_id = request.get("node_id")
                if node_id in (None, ""):
                    raise ValueError("node_id mangler")
                position = bridge.position(node_id)
                response = {
                    "ok": True,
                    "found": position is not None,
                    "position": position,
                    "revision": bridge.position_store.current_revision(
                        bridge.route_key
                    ),
                    "route_key": bridge.route_key,
                }
            elif command == "position_status":
                response = {
                    "ok": True,
                    "position_status": bridge.position_status(),
                }
            elif command == "position_history":
                since = int(request.get("since_sequence", 0))
                limit = int(request.get("limit", 50))
                positions, more = bridge.position_history(
                    since_sequence=since,
                    limit=limit,
                )
                response = {
                    "ok": True,
                    "positions": positions,
                    "sequence": (
                        int(positions[-1]["sequence"])
                        if positions
                        else bridge.position_store.current_history_sequence(
                            bridge.route_key
                        )
                    ),
                    "more": more,
                    "total_count": bridge.position_store.history_count(
                        bridge.route_key
                    ),
                    "route_key": bridge.route_key,
                }
            elif command == "outbox":
                response = {
                    "ok": True,
                    "outbox": bridge.store.gateway_outbox_rows(bridge.route_key),
                }
            elif command == "outbox_history":
                response = {
                    "ok": True,
                    "history": bridge.store.gateway_queue_history(
                        str(request["request_id"]),
                        bridge.route_key,
                        int(request.get("limit", 50)),
                    ),
                }
            elif command == "retry":
                ok = bridge.store.retry_gateway_request(
                    str(request["request_id"]), bridge.route_key
                )
                response = {"ok": ok, "error": "Fant ikke meldingen i Base-køen"}
            elif command == "pause":
                ok = bridge.store.pause_gateway_request(
                    str(request["request_id"]), bridge.route_key
                )
                response = {
                    "ok": ok,
                    "error": "Meldingen kunne ikke pauses (den kan være aktiv eller ferdig)",
                }
            elif command == "resume":
                ok = bridge.store.resume_gateway_request(
                    str(request["request_id"]), bridge.route_key
                )
                response = {
                    "ok": ok,
                    "error": "Fant ikke en pauset melding i Base-køen",
                }
            elif command == "renew":
                ok = bridge.store.renew_gateway_request(
                    str(request["request_id"]),
                    bridge.route_key,
                    ttl_hours=float(
                        request.get("ttl_hours", bridge.gateway_ttl_hours)
                    ),
                )
                response = {
                    "ok": ok,
                    "error": "Fant ikke en utløpt, beholdt melding i Base-køen",
                }
            elif command == "cancel":
                ok = bridge.store.cancel_gateway_request(
                    str(request["request_id"]), bridge.route_key
                )
                response = {"ok": ok, "error": "Fant ikke meldingen i Base-køen"}
            elif command == "queue":
                destination = request.get("destination", "^all")
                request_id = str(request.get("request_id") or uuid.uuid4().hex[:12])
                row, created = bridge._queue_gateway_message(
                    request_id=request_id,
                    destination=destination,
                    channel=int(request.get("channel_index", bridge.channel_index)),
                    text=str(request["text"]),
                    source_label=str(request.get("source_label") or bridge.local_name),
                    waveshare_source=None,
                    protocol_name="LC3",
                    priority=int(request.get("priority", 100)),
                )
                response = {
                    "ok": True,
                    "request_id": request_id,
                    "queued": True,
                    "created": created,
                    "state": row.get("state"),
                }
            elif command == "send":
                destination = request.get("destination", "^all")
                packet_id = bridge.send_text(
                    str(request["text"]),
                    destination,
                    int(request.get("channel_index", bridge.channel_index)),
                )
                response = {
                    "ok": True,
                    "packet_id": packet_id,
                    "ack_expected": destination_to_num(destination) != BROADCAST_NUM,
                }
            else:
                response = {"ok": False, "error": "Ukjent kommando"}
        except Exception as exc:
            response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        self.wfile.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))


class ApiServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def verify_request(self, request: Any, client_address: Any) -> bool:
        # Defense in depth: hardware profiles already require 127.0.0.1, but
        # reject non-loopback peers even if a legacy/custom config binds wider.
        return is_loopback_client(client_address)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    from hardware_profile_runtime import load_runtime_config

    config = load_runtime_config(Path(args.config))
    bridge = MeshBridge(config)
    bridge.start()
    server = ApiServer((bridge.api_host, bridge.api_port), ApiHandler)
    server.bridge = bridge  # type: ignore[attr-defined]

    def request_stop(signum: int, frame: Any) -> None:
        LOG.info("Stoppsignal mottatt")
        bridge.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    LOG.info("Meshtastic API lytter på %s:%s", bridge.api_host, bridge.api_port)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        bridge.stop()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
