#!/usr/bin/env python3
from __future__ import annotations

from contextlib import contextmanager

import argparse
import copy
import json
import logging
import os
import signal
import socket
import socketserver
import stat
import struct
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
from map_publication_control_authorization_v3 import AuthorizationBroker
from map_pub_meshbridge_proxy_adapter_v3 import ProcessProxyFeedServer, GuToChatProxySerialInterface
from map_publication_transport_v1 import PublicationTransportManager
from map_pub_host_runtime_status_v1 import read_host_runtime_status
from map_pub_remote_status_v1 import derive_remote_map_status
from map_pub_host_control_client_v1 import HostMapPublicationControlClient
from aprs_sync_provider import AprsSyncProvider
from remote_base_control import RemoteBaseControl, RemoteBaseStatus
from aprs_igate_control_transport_v1 import read_status as aprs_igate_read_status, activate as aprs_igate_activate, deactivate as aprs_igate_deactivate
from roles import infer_role_from_config

from mesh_receive_health import observed_interface_class, receive_health_snapshot, transport_failure

import meshtastic.serial_interface
from pubsub import pub

from message_store import MessageStore
from sqlite_resilience import sqlite_locked_retry
from lc3_replay_store import LC3ReplayStore
from node_catalog import NodeCatalog
from position_store import PositionStore
from protocol import (
    ControlAuthenticator,
    StatusAuthenticator,
    canonical_meshtastic_id,
    destination_to_num,
    encode_gateway_ack,
    encode_gateway_delivered,
    encode_gateway_error,
    encode_gateway_nak,
    encode_gateway_queued,
    encode_gateway_identity,
    encode_info,
    encode_aprs_history_done,
    encode_aprs_history_sync,
    encode_base_status_result,
    encode_base_control_result,
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


LOG = logging.getLogger("meshbridge")
BROADCAST_NUM = 0xFFFFFFFF
APP_VERSION = "2.5.0-beta5"
MAP_PUBLICATION_CONTROL_NODE_ID = "!0400a3ac"
MAP_PUBLICATION_BINDING_PATH = Path("/etc/gutochat/map-publication-binding-v1.json")
MAP_PUBLICATION_BINDING_SCHEMA = "gutochat.map.publication.binding.v1"
MAP_PUBLICATION_BINDING_NETWORK = "mesh868"
MAP_PUBLICATION_CONTROL_SOCKET_DEFAULT = "~/.config/lorachat-v2/private/map-publication-control.sock"


ObservedSerialInterface = observed_interface_class(meshtastic.serial_interface.SerialInterface)
ObservedProxySerialInterface = observed_interface_class(GuToChatProxySerialInterface)

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
                    created_at TEXT NOT NULL,
                    created_epoch REAL
                )
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_message_events_route_sequence "
                "ON message_events(route, sequence)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_message_events_retention_epoch "
                "ON message_events(created_epoch, sequence)"
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
        stamp = now_iso()
        created_epoch = datetime.fromisoformat(stamp).timestamp()
        con.execute(
            """
            INSERT INTO message_events(
                route, message_uid, event_type, payload_json, created_at, created_epoch
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                route,
                message_uid,
                event_type,
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                stamp,
                created_epoch,
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
        self.role = infer_role_from_config(config)
        self.field_base_parity_enabled = bool(config.get("field_base_parity_enabled", False))
        self.aprs_field_sync_enabled = bool(config.get("aprs_field_sync_enabled", self.field_base_parity_enabled))
        self.remote_base_control_enabled = bool(config.get("remote_base_control_enabled", False))
        self.remote_base_control_route = (
            str(config.get("remote_base_control_route", "mesh868")).strip() or "mesh868"
        )
        raw_allowlist = config.get("remote_base_control_field_addresses", [])
        self.remote_base_control_field_addresses = {
            int(value) for value in raw_allowlist
            if str(value).strip().isdigit() and 0 < int(value) < 65535
        } if isinstance(raw_allowlist, (list, tuple, set)) else set()
        self.remote_base_status_enabled = bool(config.get("remote_base_status_enabled", False))
        self.remote_base_status_route = (
            str(config.get("remote_base_status_route", self.remote_base_control_route)).strip()
            or self.remote_base_control_route
        )
        raw_status_allowlist = config.get("remote_base_status_field_addresses", [])
        self.remote_base_status_field_addresses = {
            int(value) for value in raw_status_allowlist
            if str(value).strip().isdigit() and 0 < int(value) < 65535
        } if isinstance(raw_status_allowlist, (list, tuple, set)) else set()
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
        self.store = sqlite_locked_retry(
            lambda: BridgeStore(db_path),
            label=f"{self.route_key} BridgeStore-oppstart",
            logger=LOG,
        )
        self.catalog = sqlite_locked_retry(
            lambda: NodeCatalog(db_path),
            label=f"{self.route_key} NodeCatalog-oppstart",
            logger=LOG,
        )
        self.position_store = sqlite_locked_retry(
            lambda: PositionStore(db_path),
            label=f"{self.route_key} PositionStore-oppstart",
            logger=LOG,
        )
        self.interrupted_pending = sqlite_locked_retry(
            lambda: self.store.interrupt_pending(self.route_key),
            label=f"{self.route_key} avbrutte pending-rader",
            logger=LOG,
        )
        recovered_gateway = sqlite_locked_retry(
            lambda: self.store.recover_gateway_outbox(self.route_key),
            label=f"{self.route_key} gateway-utboks-gjenoppretting",
            logger=LOG,
        )
        seeded_events = sqlite_locked_retry(
            lambda: self.store.seed_message_events(self.route_key, self.network_name),
            label=f"{self.route_key} meldingssynk-startseed",
            logger=LOG,
        )
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
        self.publication_control_lock = threading.Lock()
        self.publication_authorization_broker = AuthorizationBroker()
        self.map_pub_host_control_client = (
            HostMapPublicationControlClient()
            if self.role == "base" and self.route_key == "mesh868" and not config.get("optional_adapter")
            else None
        )
        self._publication_control_in_progress = False
        self._publication_control_unverified = False
        self.map_pub_proxy_feed_server = (
            ProcessProxyFeedServer()
            if self.role == "base" and self.route_key == "mesh868" and not config.get("optional_adapter")
            else None
        )
        self.publication_transport_manager = (
            PublicationTransportManager(self, self.map_pub_proxy_feed_server)
            if self.map_pub_proxy_feed_server is not None
            else None
        )
        self.control_auth = ControlAuthenticator.from_environment(
            sqlite_locked_retry(
                lambda: LC3ReplayStore(db_path),
                label=f"{self.route_key} LC3 replay-store-oppstart",
                logger=LOG,
            )
        )
        self.status_auth = StatusAuthenticator.from_environment(
            sqlite_locked_retry(
                lambda: LC3ReplayStore(db_path),
                label=f"{self.route_key} LC3 status replay-store-oppstart",
                logger=LOG,
            )
        )
        if self.control_auth.enabled:
            LOG.info(
                "LC3-auth konfigurert (send=%s, required=%s, key_id=%s)",
                self.control_auth.send_authenticated,
                self.control_auth.require_authenticated,
                self.control_auth.key_id,
            )
        if self.status_auth.enabled:
            LOG.info("LC3 status-auth konfigurert (key_id=%s)", self.status_auth.key_id)

        self.aprs_sync_provider = None
        self.remote_base_status = None
        self.remote_base_control = None
        if self.role == "base" and self.aprs_field_sync_enabled:
            aprs_path = Path(str(config.get("map_aprs_database") or config["database"])).expanduser()
            self.aprs_sync_provider = AprsSyncProvider(aprs_path)
        if (
            self.role == "base"
            and self.remote_base_status_enabled
            and self.route_key == self.remote_base_status_route
        ):
            self.remote_base_status = RemoteBaseStatus(
                map_status=self.remote_publication_status,
                aprs_status=aprs_igate_read_status,
            )
        if (
            self.role == "base"
            and self.remote_base_control_enabled
            and self.route_key == self.remote_base_control_route
        ):
            remote_control_db = Path(
                str(
                    config.get(
                        "remote_base_control_database",
                        db_path.parent / "remote-base-control.sqlite3",
                    )
                )
            ).expanduser()
            self.remote_base_control = RemoteBaseControl(
                remote_control_db,
                map_status=self.remote_publication_status,
                map_authorize=self.effective_publication_authorization,
                map_control=lambda target, token: self.effective_publication_control(
                    target, authorization_token=token
                ),
                aprs_status=aprs_igate_read_status,
                aprs_activate=aprs_igate_activate,
                aprs_deactivate=aprs_igate_deactivate,
            )

        cursor = sqlite_locked_retry(
            lambda: self.store.get_state_int(self.cursor_key),
            label=f"{self.route_key} cursor-lesing",
            logger=LOG,
        )
        if cursor is None:
            cursor = sqlite_locked_retry(
                self.store.max_message_id,
                label=f"{self.route_key} maksimum meldings-ID",
                logger=LOG,
            )
            sqlite_locked_retry(
                lambda: self.store.set_state_int(self.cursor_key, cursor),
                label=f"{self.route_key} cursor-initiering",
                logger=LOG,
            )
        self.ws_cursor = cursor

        pub.subscribe(self._on_receive_text, "meshtastic.receive.text")
        pub.subscribe(self._on_receive_position, "meshtastic.receive.position")
        pub.subscribe(self._on_connection, "meshtastic.connection.established")
        pub.subscribe(self._on_connection_lost, "meshtastic.connection.lost")
        pub.subscribe(self._on_node_updated, "meshtastic.node.updated")

    def start(self) -> None:
        if self.map_pub_proxy_feed_server is not None:
            self.map_pub_proxy_feed_server.start()
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
        try:
            if self.map_pub_proxy_feed_server is not None:
                self.map_pub_proxy_feed_server.close()
        except Exception:
            LOG.exception("Kunne ikke lukke MAP-PUB proxy-feed-server")

    def _bind_receive_interface(self, interface: Any) -> None:
        self.interface = interface

    def _mesh_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.connection_lost.clear()
                LOG.info("Kobler til Meshtastic-radio på %s", self.serial_port)
                if self.map_pub_proxy_feed_server is not None:
                    self.interface = ObservedProxySerialInterface(
                        devPath=self.serial_port,
                        proxy_server=self.map_pub_proxy_feed_server,
                        _guto_bind_interface=self._bind_receive_interface,
                    )
                else:
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
                    "source": str(row.get("source", "")),
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

    def _remote_map_authorize(self, target: str) -> dict[str, Any]:
        expected, error = self._publication_control_expected_node_id()
        if error is not None or expected is None:
            return {"authorized": False, "reason_code": error or "BINDING_INVALID"}
        return self.publication_authorization(target, expected)

    def _remote_status_allowed(self, source: int, verified: Any) -> bool:
        return bool(
            self.role == "base"
            and self.remote_base_status_enabled
            and self.remote_base_status is not None
            and self.route_key == self.remote_base_status_route
            and self.status_auth.enabled
            and verified is not None
            and int(source) in self.remote_base_status_field_addresses
        )

    def _privileged_remote_allowed(self, source: int, verified: Any) -> bool:
        return bool(
            self.role == "base"
            and self.remote_base_control_enabled
            and self.remote_base_control is not None
            and self.route_key == self.remote_base_control_route
            and self.control_auth.enabled
            and verified is not None
            and int(source) in self.remote_base_control_field_addresses
        )

    def _send_waveshare_status_control(self, destination: int, text: str) -> None:
        """Always HMAC-wrap read-only status results with the status credential."""
        if not self.status_auth.enabled:
            raise RuntimeError("REMOTE_STATUS_AUTH_NOT_CONFIGURED")
        wire_text = self.status_auth.wrap(text)
        frames = fragment_frame(
            wire_text,
            max_bytes=self.max_control_bytes,
            max_fragments=self.max_fragments,
        )
        policy = control_transport_policy(text, destination)
        for frame in frames:
            request = {"command": "send", "destination": int(destination), "text": frame}
            request.update(policy)
            json_api_call(self.lorad_host, self.lorad_port, request)

    def _send_waveshare_privileged_control(self, destination: int, text: str) -> None:
        """Always HMAC-wrap remote-control results, independent of compatibility send mode."""
        if not self.control_auth.enabled:
            raise RuntimeError("REMOTE_CONTROL_AUTH_NOT_CONFIGURED")
        wire_text = self.control_auth.wrap(text)
        frames = fragment_frame(
            wire_text,
            max_bytes=self.max_control_bytes,
            max_fragments=self.max_fragments,
        )
        policy = control_transport_policy(text, destination)
        for frame in frames:
            request = {"command": "send", "destination": int(destination), "text": frame}
            request.update(policy)
            json_api_call(self.lorad_host, self.lorad_port, request)

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

                expired_pending = sqlite_locked_retry(
                    lambda: self.store.expire_pending(self.route_key),
                    label=f"{self.route_key} expire_pending runtime",
                    logger=LOG,
                    attempts=2,
                    initial_delay=0.10,
                    max_delay=0.25,
                )
                for row in expired_pending:
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
        control_verified = None
        status_verified = None
        try:
            if self.status_auth.is_authenticated_frame(raw_text):
                raw_text, status_verified = self.status_auth.decode_inbound(
                    raw_text,
                    live=True,
                )
            else:
                raw_text, control_verified = self.control_auth.decode_inbound(
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
        if status_verified is not None and command != "BASE_STATUS_REQ":
            LOG.warning(
                "Avviser status-autentisert ikke-statuskommando %s fra Waveshare %s",
                command, source,
            )
            return True
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
            if command == "AREQ":
                provider = self.aprs_sync_provider
                if self.role != "base" or not self.aprs_field_sync_enabled or provider is None:
                    return True
                since = int(control.get("since_sequence", 0))
                limit = int(control.get("limit", 10))
                try:
                    if since == 0:
                        observations, more, baseline, page_after = provider.snapshot_page(
                            int(control.get("snapshot_baseline", 0)),
                            int(control.get("snapshot_after", 0)),
                            limit,
                        )
                        for observation in observations:
                            self._send_waveshare_control(
                                source,
                                encode_aprs_history_sync(
                                    request_id, self.route_key,
                                    int(observation["sequence"]), observation,
                                ),
                            )
                        self._send_waveshare_control(
                            source,
                            encode_aprs_history_done(
                                request_id, self.route_key, page_after,
                                len(observations), more,
                                snapshot_baseline=baseline,
                                snapshot_after=page_after,
                            ),
                        )
                    else:
                        observations, more, last_sequence = provider.history_since(since, limit)
                        for observation in observations:
                            self._send_waveshare_control(
                                source,
                                encode_aprs_history_sync(
                                    request_id, self.route_key,
                                    int(observation["sequence"]), observation,
                                ),
                            )
                        self._send_waveshare_control(
                            source,
                            encode_aprs_history_done(
                                request_id, self.route_key, last_sequence,
                                len(observations), more,
                            ),
                        )
                except ValueError as exc:
                    if str(exc) not in {
                        "APRS_CURSOR_AHEAD_OF_BASE",
                        "APRS_SNAPSHOT_BASELINE_AHEAD_OF_BASE",
                        "APRS_SNAPSHOT_AFTER_AHEAD_OF_BASELINE",
                    }:
                        raise
                    self._send_waveshare_control(
                        source,
                        encode_aprs_history_done(
                            request_id, self.route_key, provider.current_sequence(),
                            0, False, resync_required=True,
                        ),
                    )
                return True
            if command == "BASE_STATUS_REQ":
                if not self._remote_status_allowed(source, status_verified):
                    LOG.warning("Avviser read-only Base-status fra Waveshare %s", source)
                    return True
                assert self.remote_base_status is not None
                status = self.remote_base_status.status(str(control.get("resource", "")))
                self._send_waveshare_status_control(
                    source,
                    encode_base_status_result(
                        request_id, self.route_key, str(status.get("resource", "")),
                        str(status.get("state", "UNKNOWN_DEGRADED")),
                        bool(status.get("verified")),
                        str(status.get("reason_code", "")),
                    ),
                )
                return True
            if command == "BASE_CONTROL_REQ":
                if not self._privileged_remote_allowed(source, control_verified):
                    LOG.warning("Avviser privilegert Base-kontroll fra Waveshare %s", source)
                    return True
                assert self.remote_base_control is not None
                result = self.remote_base_control.handle_control(
                    request_id=request_id,
                    source=source,
                    resource=str(control.get("resource", "")),
                    expected_state=str(control.get("expected_state", "")),
                    target_state=str(control.get("target_state", "")),
                )
                self._send_waveshare_privileged_control(
                    source,
                    encode_base_control_result(
                        request_id, self.route_key, str(result.get("resource", "")),
                        str(result.get("source_state", control.get("expected_state", "UNKNOWN_DEGRADED"))),
                        str(result.get("target_state", control.get("target_state", "UNKNOWN_DEGRADED"))),
                        str(result.get("state", "UNKNOWN_DEGRADED")),
                        bool(result.get("ok")), bool(result.get("verified")),
                        str(result.get("reason_code", "")),
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

    def publication_status(
        self, expected_node_id: str | None = None
    ) -> dict[str, Any]:
        """Return cached B868 MQTT publication state without device writes.

        The method deliberately reads only the already-connected Meshtastic
        ``localNode`` cache. It must not request fresh config, touch SQLite,
        or invoke any Meshtastic write method. Callers must treat
        ``UNKNOWN_DEGRADED`` as fail-closed rather than assuming publication
        is disabled.
        """
        publisher_node_id = canonical_meshtastic_id(
            self.local_id or None,
            node_num=self.local_num or None,
        )
        expected = (
            canonical_meshtastic_id(expected_node_id)
            if expected_node_id not in (None, "")
            else None
        )

        result: dict[str, Any] = {
            "state": "UNKNOWN_DEGRADED",
            "reason_code": "STATE_NOT_READ",
            "publisher_node_id": publisher_node_id or None,
            "expected_node_id": expected,
            "identity_match": (
                publisher_node_id == expected
                if expected is not None and publisher_node_id
                else None
            ),
            "mqtt_enabled": None,
            "map_reporting_enabled": None,
            "proxy_to_client_enabled": None,
            "active_channel_indices": None,
            "uplink_channel_indices": None,
            "channel_state_complete": False,
            "publication_path_configured": None,
            "effective_publication_enabled": None,
            "read_source": "existing_serial_interface_cached_state",
        }

        if getattr(self, "_publication_control_in_progress", False):
            result["reason_code"] = "CONTROL_OPERATION_IN_PROGRESS"
            return result
        if getattr(self, "_publication_control_unverified", False):
            result["reason_code"] = "CONTROL_STATE_UNVERIFIED"
            return result
        transport_manager = getattr(self, "publication_transport_manager", None)
        if transport_manager is not None and transport_manager.control_state() != "VERIFIED":
            result["reason_code"] = "TRANSPORT_CONTROL_STATE_UNVERIFIED"
            return result

        if not publisher_node_id:
            result["reason_code"] = "PUBLISHER_ID_UNAVAILABLE"
            return result
        if expected is not None and publisher_node_id != expected:
            result["reason_code"] = "IDENTITY_MISMATCH"
            return result
        if not self.online:
            result["reason_code"] = "BRIDGE_OFFLINE"
            return result
        if self.interface is None:
            result["reason_code"] = "SERIAL_INTERFACE_UNAVAILABLE"
            return result

        local_node = getattr(self.interface, "localNode", None)
        if local_node is None:
            result["reason_code"] = "LOCAL_NODE_UNAVAILABLE"
            return result

        module_config = getattr(local_node, "moduleConfig", None)
        if module_config is None:
            result["reason_code"] = "MODULE_CONFIG_UNAVAILABLE"
            return result

        has_field = getattr(module_config, "HasField", None)
        if callable(has_field):
            try:
                if not has_field("mqtt"):
                    result["reason_code"] = "MQTT_CONFIG_NOT_LOADED"
                    return result
            except Exception:
                result["reason_code"] = "MQTT_CONFIG_PRESENCE_UNKNOWN"
                return result

        mqtt = getattr(module_config, "mqtt", None)
        if mqtt is None:
            result["reason_code"] = "MQTT_CONFIG_UNAVAILABLE"
            return result

        mqtt_enabled = bool(getattr(mqtt, "enabled", False))
        map_reporting_enabled = bool(
            getattr(mqtt, "map_reporting_enabled", False)
        )
        proxy_to_client_enabled = bool(
            getattr(mqtt, "proxy_to_client_enabled", False)
        )
        result.update(
            {
                "mqtt_enabled": mqtt_enabled,
                "map_reporting_enabled": map_reporting_enabled,
                "proxy_to_client_enabled": proxy_to_client_enabled,
            }
        )

        channels = getattr(local_node, "channels", None)
        active_indices: list[int] | None = None
        uplink_indices: list[int] | None = None
        if channels is not None:
            try:
                channel_rows = list(channels)
            except TypeError:
                channel_rows = []
            if channel_rows:
                active_indices = []
                uplink_indices = []
                for position, channel in enumerate(channel_rows):
                    try:
                        index = int(getattr(channel, "index", position))
                    except (TypeError, ValueError):
                        index = position
                    try:
                        role = int(getattr(channel, "role", 0))
                    except (TypeError, ValueError):
                        role = 0
                    if role == 0:
                        continue
                    active_indices.append(index)
                    settings = getattr(channel, "settings", None)
                    if settings is not None and bool(
                        getattr(settings, "uplink_enabled", False)
                    ):
                        uplink_indices.append(index)

        channel_state_complete = active_indices is not None
        result["active_channel_indices"] = active_indices
        result["uplink_channel_indices"] = uplink_indices
        result["channel_state_complete"] = channel_state_complete

        if map_reporting_enabled:
            publication_path_configured: bool | None = True
        elif uplink_indices is not None:
            publication_path_configured = bool(uplink_indices)
        else:
            publication_path_configured = None

        result["publication_path_configured"] = publication_path_configured
        result["effective_publication_enabled"] = (
            mqtt_enabled and publication_path_configured
            if publication_path_configured is not None
            else None
        )

        if mqtt_enabled:
            result["state"] = "ON"
            if publication_path_configured is True:
                result["reason_code"] = "MQTT_ENABLED_PATH_PRESENT"
            elif publication_path_configured is False:
                result["reason_code"] = "MQTT_ENABLED_NO_KNOWN_PATH"
            else:
                result["reason_code"] = "MQTT_ENABLED_CHANNEL_STATE_UNKNOWN"
        else:
            result["state"] = "OFF"
            result["reason_code"] = "MQTT_DISABLED"
            result["effective_publication_enabled"] = False

        return result

    def remote_publication_status(self) -> dict[str, Any]:
        """Return effective MAP_PUB state for authenticated Field readback.

        DEVICE_DIRECT/NONE preserve the existing device-MQTT semantics.  When
        HOST_PROXY owns transport, externally effective publication is derived
        from verified device/path state, feed-consumer presence and the
        non-secret host runtime arm heartbeat.  No device or arm write occurs.
        """
        expected, error = self._publication_control_expected_node_id()
        if error or expected is None:
            return {
                "state": "UNKNOWN_DEGRADED",
                "verified": False,
                "identity_match": None,
                "reason_code": error or "EXPECTED_ID_UNAVAILABLE",
            }
        device = self.publication_status(expected)
        transport = self.publication_transport_status(expected)
        host = None
        if str(transport.get("transport_owner", "UNKNOWN")).upper() == "HOST_PROXY":
            host = read_host_runtime_status()
        result = derive_remote_map_status(device, transport, host)
        result["transport_owner"] = str(transport.get("transport_owner", "UNKNOWN"))
        result["publisher_node_id"] = transport.get("publisher_node_id", device.get("publisher_node_id"))
        result["expected_node_id"] = transport.get("expected_node_id", device.get("expected_node_id", expected))
        result["mqtt_enabled"] = device.get("mqtt_enabled")
        result["publication_path_configured"] = transport.get("publication_path_configured")
        client = getattr(self, "map_pub_host_control_client", None)
        if str(result.get("transport_owner", "")).upper() == "HOST_PROXY" and client is not None:
            try:
                ctl = client.status()
                result["host_control_available"] = ctl.get("verified") is True
            except Exception:
                result["host_control_available"] = False
        return result

    def effective_publication_authorization(
        self, target_state: str, expected_node_id: str | None = None
    ) -> dict[str, Any]:
        """Issue a one-shot authorization for the effective publication owner.

        HOST_PROXY never writes B868 MQTT configuration; it authorizes only the
        root-owned host arm controller. DEVICE_DIRECT retains the legacy path.
        """
        status = self.remote_publication_status()
        owner = str(status.get("transport_owner", "UNKNOWN")).upper()
        if owner != "HOST_PROXY":
            return self.publication_authorization(target_state, expected_node_id)
        target = str(target_state or "").strip().upper()
        expected, error = self._publication_control_expected_node_id()
        requested = canonical_meshtastic_id(expected_node_id) if expected_node_id else expected
        if error or expected is None or requested != expected:
            return {"authorized": False, "reason_code": error or "EXPECTED_NODE_ID_MISMATCH"}
        source = str(status.get("state", "UNKNOWN_DEGRADED")).upper()
        if status.get("verified") is not True or source not in {"ON", "OFF"}:
            return {"authorized": False, "reason_code": "EFFECTIVE_SOURCE_STATE_UNVERIFIED"}
        if status.get("host_control_available") is not True:
            return {"authorized": False, "reason_code": "HOST_CONTROL_UNAVAILABLE"}
        if target not in {"ON", "OFF"} or target == source:
            return {"authorized": False, "reason_code": "TARGET_NOT_OPPOSITE_EFFECTIVE_STATE"}
        return self.publication_authorization_broker.issue(
            expected_node_id=expected, source_state=source, target_state=target
        )

    def effective_publication_control(
        self, target_state: str, *, authorization_token: str | None = None
    ) -> dict[str, Any]:
        """Control effective MAP_PUB state without changing B868 transport policy."""
        target = str(target_state or "").strip().upper()
        status = self.remote_publication_status()
        owner = str(status.get("transport_owner", "UNKNOWN")).upper()
        if owner != "HOST_PROXY":
            return self.publication_control(target, authorization_token=authorization_token)
        expected, error = self._publication_control_expected_node_id()
        if error or expected is None:
            return self._publication_control_result(error or "BLOCKED_BINDING_INVALID", target_state=target)
        source = str(status.get("state", "UNKNOWN_DEGRADED")).upper()
        auth = self.publication_authorization_broker.consume(
            authorization_token, expected_node_id=expected, target_state=target
        )
        if auth.get("authorized") is not True:
            return self._publication_control_result(
                "BLOCKED_" + str(auth.get("reason_code") or "AUTHORIZATION_INVALID"),
                target_state=target,
            )
        if str(auth.get("source_state", "")) != source:
            return self._publication_control_result("BLOCKED_EFFECTIVE_SOURCE_CHANGED", target_state=target)
        if status.get("verified") is not True or source not in {"ON", "OFF"} or source == target:
            return self._publication_control_result("BLOCKED_EFFECTIVE_STATE_UNVERIFIED", target_state=target)
        client = getattr(self, "map_pub_host_control_client", None)
        if client is None:
            return self._publication_control_result("BLOCKED_HOST_CONTROL_UNAVAILABLE", target_state=target)
        request_id = str(auth.get("operation_id") or uuid.uuid4())
        try:
            operation = client.set_state(target, request_id=request_id)
        except Exception:
            operation = {"ok": False, "verified": False, "result_code": "HOST_CONTROL_TRANSPORT_FAILED"}
        deadline = time.monotonic() + 25.0
        after: dict[str, Any] = {}
        while time.monotonic() < deadline:
            after = self.remote_publication_status()
            if after.get("verified") is True and str(after.get("state", "")).upper() == target:
                break
            time.sleep(0.2)
        verified = after.get("verified") is True and str(after.get("state", "")).upper() == target
        if verified:
            code = "ACTIVATED_ON" if target == "ON" else "DEACTIVATED_OFF"
        else:
            code = str(operation.get("result_code") or after.get("reason_code") or "TARGET_NOT_VERIFIED")
        return {
            "result_code": code,
            "target_state": target,
            "state": str(after.get("state", "UNKNOWN_DEGRADED")),
            "publisher_node_id": after.get("publisher_node_id"),
            "verified": bool(verified),
            "write_sent": bool(operation.get("ok")),
            "host_proxy_control": True,
        }

    def _publication_control_expected_node_id(
        self,
    ) -> tuple[str | None, str | None]:
        """Read and validate the dedicated root-owned MAP-PUB trust anchor.

        The APRS-pinned shared config.json is deliberately not consulted.
        Every control operation re-validates schema, network, ownership,
        permissions, and the fixed B868 node identity before any device write.
        """
        raw_path = getattr(
            self, "map_publication_binding_path", MAP_PUBLICATION_BINDING_PATH
        )
        path = raw_path if hasattr(raw_path, "read_text") else Path(raw_path)
        try:
            st = path.stat()
        except Exception:
            return None, "BLOCKED_EXPECTED_ID_NOT_CONFIGURED"
        try:
            uid = int(getattr(st, "st_uid"))
            gid = int(getattr(st, "st_gid"))
            mode = int(getattr(st, "st_mode"))
        except Exception:
            return None, "BLOCKED_TRUST_ANCHOR_PERMISSIONS"
        if uid != 0 or gid != 0 or (mode & 0o022):
            return None, "BLOCKED_TRUST_ANCHOR_PERMISSIONS"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None, "BLOCKED_EXPECTED_ID_NOT_CONFIGURED"
        if not isinstance(data, dict):
            return None, "BLOCKED_EXPECTED_ID_NOT_CONFIGURED"
        if data.get("schema") != MAP_PUBLICATION_BINDING_SCHEMA:
            return None, "BLOCKED_EXPECTED_ID_NOT_CONFIGURED"
        if data.get("network") != MAP_PUBLICATION_BINDING_NETWORK:
            return None, "BLOCKED_EXPECTED_ID_NOT_CONFIGURED"
        configured_raw = data.get("expected_node_id")
        if configured_raw in (None, ""):
            return None, "BLOCKED_EXPECTED_ID_NOT_CONFIGURED"
        try:
            expected = canonical_meshtastic_id(configured_raw)
            if (
                len(expected) != 9
                or not expected.startswith("!")
                or any(ch not in "0123456789abcdef" for ch in expected[1:])
            ):
                expected = ""
        except Exception:
            expected = ""
        if not expected:
            return None, "BLOCKED_EXPECTED_ID_NOT_CONFIGURED"
        if expected != MAP_PUBLICATION_CONTROL_NODE_ID:
            return expected, "BLOCKED_IDENTITY_MISMATCH"
        return expected, None

    @staticmethod
    def _publication_mqtt_non_target_equal(before: Any, after: Any) -> bool:
        """Compare complete MQTT messages while ignoring only ``enabled``.

        Copies remain in memory and are never logged or returned.  Protobuf
        message equality is semantic; the same helper also works with the
        deliberately protobuf-shaped fakes used by the isolated A1-4 tests.
        """
        try:
            before_copy = copy.deepcopy(before)
            after_copy = copy.deepcopy(after)
            setattr(before_copy, "enabled", False)
            setattr(after_copy, "enabled", False)
            return bool(before_copy == after_copy)
        except Exception:
            return False

    def publication_authorization(
        self, target_state: str, expected_node_id: str | None
    ) -> dict[str, Any]:
        """Issue one short-lived backend capability for the opposite state.

        This method is write-free.  It reuses the control lock to bind issuance
        to one verified B868 identity/status snapshot.  The returned bearer
        capability is kept only as a digest in process memory and must be
        consumed by exactly one subsequent ``publication_control`` call.
        """
        target = str(target_state or "").strip().upper()
        if target not in {"ON", "OFF"}:
            return {"authorized": False, "reason_code": "BLOCKED_INVALID_TARGET"}
        control_lock = getattr(self, "publication_control_lock", None)
        if control_lock is None or not control_lock.acquire(blocking=False):
            return {"authorized": False, "reason_code": "CONTROL_BUSY"}
        try:
            expected, binding_error = self._publication_control_expected_node_id()
            if binding_error is not None or expected is None:
                return {
                    "authorized": False,
                    "reason_code": binding_error or "BLOCKED_BINDING_INVALID",
                }
            requested = canonical_meshtastic_id(str(expected_node_id or "").strip())
            if requested != expected:
                return {"authorized": False, "reason_code": "BLOCKED_IDENTITY_MISMATCH"}
            if getattr(self, "_publication_control_unverified", False) or getattr(
                self, "_publication_control_in_progress", False
            ):
                return {
                    "authorized": False,
                    "reason_code": "BLOCKED_PREVIOUS_CONTROL_UNVERIFIED",
                }
            transport_manager = getattr(self, "publication_transport_manager", None)
            if transport_manager is not None and transport_manager.control_state() != "VERIFIED":
                return {
                    "authorized": False,
                    "reason_code": "BLOCKED_TRANSPORT_CONTROL_UNVERIFIED",
                }
            if not bool(getattr(self, "online", False)):
                return {"authorized": False, "reason_code": "BLOCKED_BRIDGE_OFFLINE"}
            publisher_node_id = canonical_meshtastic_id(
                getattr(self, "local_id", None) or None,
                node_num=getattr(self, "local_num", None) or None,
            )
            if publisher_node_id != expected:
                return {"authorized": False, "reason_code": "BLOCKED_IDENTITY_MISMATCH"}
            status = self.publication_status(expected)
            source = str(status.get("state", "UNKNOWN_DEGRADED")).strip().upper()
            if source not in {"ON", "OFF"}:
                return {
                    "authorized": False,
                    "reason_code": "BLOCKED_STATUS_NOT_WRITE_ELIGIBLE",
                }
            required_target = "ON" if source == "OFF" else "OFF"
            if target != required_target:
                return {
                    "authorized": False,
                    "reason_code": "BLOCKED_TARGET_NOT_OPPOSITE_CURRENT_STATE",
                }
            if target == "ON" and status.get("publication_path_configured") is not True:
                return {
                    "authorized": False,
                    "reason_code": "ACTIVATION_BLOCKED_NO_EXISTING_PUBLICATION_PATH",
                }
            broker = getattr(self, "publication_authorization_broker", None)
            if broker is None:
                return {
                    "authorized": False,
                    "reason_code": "BLOCKED_AUTHORIZATION_BROKER_UNAVAILABLE",
                }
            return broker.issue(
                expected_node_id=expected,
                source_state=source,
                target_state=target,
            )
        except Exception:
            return {"authorized": False, "reason_code": "AUTHORIZATION_INTERNAL_ERROR"}
        finally:
            control_lock.release()

    @staticmethod
    def _publication_control_result(
        code: str,
        *,
        state: str = "UNKNOWN_DEGRADED",
        target_state: str | None = None,
        publisher_node_id: str | None = None,
        write_sent: bool = False,
        verified: bool = False,
    ) -> dict[str, Any]:
        return {
            "result_code": code,
            "state": state,
            "target_state": target_state,
            "publisher_node_id": publisher_node_id,
            "write_sent": bool(write_sent),
            "verified": bool(verified),
            "reboot_expected": bool(write_sent),
        }

    def publication_control(
        self,
        target_state: str,
        *,
        authorization_token: str | None = None,
        reconnect_timeout_seconds: float = 75.0,
        poll_interval_seconds: float = 0.10,
    ) -> dict[str, Any]:
        """Set only B868 ``mqtt.enabled`` under the A1-3 fail-closed contract.

        This source candidate intentionally uses the already-owned
        SerialInterface.  It never opens a second radio client, never writes a
        channel, and never logs or returns the complete MQTT protobuf.  A
        successful result requires a new SerialInterface after the expected
        radio reboot plus identity/config readback and non-target-field
        preservation.
        """
        target = str(target_state or "").strip().upper()
        if target not in {"ON", "OFF"}:
            return self._publication_control_result(
                "BLOCKED_INVALID_TARGET", target_state=target or None
            )
        desired_enabled = target == "ON"

        control_lock = getattr(self, "publication_control_lock", None)
        if control_lock is None:
            return self._publication_control_result(
                "BLOCKED_CONTROL_LOCK_UNAVAILABLE", target_state=target
            )
        if not control_lock.acquire(blocking=False):
            return self._publication_control_result(
                "CONTROL_BUSY", target_state=target
            )

        snapshot: Any = None
        original_interface: Any = None
        write_sent = False
        publisher_node_id: str | None = None
        try:
            expected, binding_error = self._publication_control_expected_node_id()
            if binding_error is not None:
                return self._publication_control_result(
                    binding_error,
                    target_state=target,
                    publisher_node_id=expected,
                )
            assert expected is not None
            broker = getattr(self, "publication_authorization_broker", None)
            if broker is None:
                return self._publication_control_result(
                    "BLOCKED_AUTHORIZATION_BROKER_UNAVAILABLE",
                    target_state=target,
                )
            authorization = broker.consume(
                authorization_token,
                expected_node_id=expected,
                target_state=target,
            )
            if authorization.get("authorized") is not True:
                reason = str(authorization.get("reason_code") or "AUTHORIZATION_INVALID")
                return self._publication_control_result(
                    "BLOCKED_" + reason,
                    target_state=target,
                )
            authorized_source_state = str(
                authorization.get("source_state", "UNKNOWN_DEGRADED")
            )
            if getattr(self, "_publication_control_unverified", False):
                return self._publication_control_result(
                    "BLOCKED_PREVIOUS_CONTROL_UNVERIFIED",
                    target_state=target,
                )
            transport_manager = getattr(self, "publication_transport_manager", None)
            if transport_manager is not None and transport_manager.control_state() != "VERIFIED":
                return self._publication_control_result(
                    "BLOCKED_TRANSPORT_CONTROL_UNVERIFIED",
                    target_state=target,
                )
            if not bool(getattr(self, "online", False)):
                return self._publication_control_result(
                    "BLOCKED_BRIDGE_OFFLINE", target_state=target
                )

            publisher_node_id = canonical_meshtastic_id(
                getattr(self, "local_id", None) or None,
                node_num=getattr(self, "local_num", None) or None,
            )
            if publisher_node_id != expected:
                return self._publication_control_result(
                    "BLOCKED_IDENTITY_MISMATCH",
                    target_state=target,
                    publisher_node_id=publisher_node_id or None,
                )

            original_interface = getattr(self, "interface", None)
            if original_interface is None:
                return self._publication_control_result(
                    "BLOCKED_BRIDGE_OFFLINE",
                    target_state=target,
                    publisher_node_id=publisher_node_id,
                )
            local_node = getattr(original_interface, "localNode", None)
            module_config = getattr(local_node, "moduleConfig", None)
            if local_node is None or module_config is None:
                return self._publication_control_result(
                    "BLOCKED_MQTT_CONFIG_NOT_LOADED",
                    target_state=target,
                    publisher_node_id=publisher_node_id,
                )
            has_field = getattr(module_config, "HasField", None)
            if not callable(has_field):
                return self._publication_control_result(
                    "BLOCKED_MQTT_CONFIG_NOT_LOADED",
                    target_state=target,
                    publisher_node_id=publisher_node_id,
                )
            try:
                mqtt_loaded = bool(has_field("mqtt"))
            except Exception:
                mqtt_loaded = False
            if not mqtt_loaded:
                return self._publication_control_result(
                    "BLOCKED_MQTT_CONFIG_NOT_LOADED",
                    target_state=target,
                    publisher_node_id=publisher_node_id,
                )
            mqtt = getattr(module_config, "mqtt", None)
            if mqtt is None:
                return self._publication_control_result(
                    "BLOCKED_MQTT_CONFIG_NOT_LOADED",
                    target_state=target,
                    publisher_node_id=publisher_node_id,
                )

            status = self.publication_status(expected)
            if str(status.get("state", "UNKNOWN_DEGRADED")).strip().upper() != authorized_source_state:
                return self._publication_control_result(
                    "BLOCKED_AUTHORIZATION_SOURCE_STATE_CHANGED",
                    target_state=target,
                    publisher_node_id=publisher_node_id,
                )
            if status.get("state") == "UNKNOWN_DEGRADED":
                return self._publication_control_result(
                    "BLOCKED_MQTT_CONFIG_NOT_LOADED",
                    target_state=target,
                    publisher_node_id=publisher_node_id,
                )
            current_enabled = bool(getattr(mqtt, "enabled", False))
            if current_enabled == desired_enabled:
                return self._publication_control_result(
                    "ALREADY_ON" if desired_enabled else "ALREADY_OFF",
                    state=target,
                    target_state=target,
                    publisher_node_id=publisher_node_id,
                    verified=True,
                )
            if desired_enabled and status.get("publication_path_configured") is not True:
                return self._publication_control_result(
                    "ACTIVATION_BLOCKED_NO_EXISTING_PUBLICATION_PATH",
                    state="OFF",
                    target_state=target,
                    publisher_node_id=publisher_node_id,
                )

            try:
                snapshot = copy.deepcopy(mqtt)
            except Exception:
                return self._publication_control_result(
                    "BLOCKED_MQTT_CONFIG_NOT_LOADED",
                    target_state=target,
                    publisher_node_id=publisher_node_id,
                )

            send_lock = getattr(self, "send_lock", None)
            if send_lock is None:
                return self._publication_control_result(
                    "BLOCKED_SEND_LOCK_UNAVAILABLE",
                    target_state=target,
                    publisher_node_id=publisher_node_id,
                )

            self._publication_control_in_progress = True
            self._publication_control_unverified = True
            with send_lock:
                # Recheck the exact interface and identity immediately before
                # the only permitted mutation to close reconnect races.
                if (
                    not bool(getattr(self, "online", False))
                    or getattr(self, "interface", None) is not original_interface
                    or canonical_meshtastic_id(
                        getattr(self, "local_id", None) or None,
                        node_num=getattr(self, "local_num", None) or None,
                    ) != expected
                ):
                    self._publication_control_in_progress = False
                    self._publication_control_unverified = False
                    return self._publication_control_result(
                        "BLOCKED_IDENTITY_MISMATCH",
                        target_state=target,
                        publisher_node_id=publisher_node_id,
                    )
                setattr(mqtt, "enabled", desired_enabled)
                try:
                    local_node.writeConfig("mqtt")
                    write_sent = True
                except Exception:
                    # The transport may have failed before or after sending;
                    # never claim the old or requested state after ambiguity.
                    return self._publication_control_result(
                        "WRITE_EXCEPTION_UNKNOWN_STATE",
                        target_state=target,
                        publisher_node_id=publisher_node_id,
                        write_sent=True,
                    )

            deadline = time.monotonic() + max(0.0, float(reconnect_timeout_seconds))
            interval = max(0.001, float(poll_interval_seconds))
            fresh_interface: Any = None
            while time.monotonic() < deadline:
                candidate = getattr(self, "interface", None)
                if (
                    candidate is not None
                    and candidate is not original_interface
                    and bool(getattr(self, "online", False))
                ):
                    fresh_interface = candidate
                    break
                time.sleep(interval)

            if fresh_interface is None:
                return self._publication_control_result(
                    "RECONNECT_TIMEOUT_UNKNOWN_STATE",
                    target_state=target,
                    publisher_node_id=publisher_node_id,
                    write_sent=write_sent,
                )

            # Re-evaluate identity from the fresh interface without touching DB.
            self._refresh_identity()
            post_publisher_id = canonical_meshtastic_id(
                getattr(self, "local_id", None) or None,
                node_num=getattr(self, "local_num", None) or None,
            )
            if post_publisher_id != expected:
                return self._publication_control_result(
                    "POST_WRITE_IDENTITY_MISMATCH",
                    target_state=target,
                    publisher_node_id=post_publisher_id or None,
                    write_sent=write_sent,
                )

            post_local_node = getattr(fresh_interface, "localNode", None)
            post_module_config = getattr(post_local_node, "moduleConfig", None)
            post_has_field = getattr(post_module_config, "HasField", None)
            if post_local_node is None or post_module_config is None or not callable(post_has_field):
                return self._publication_control_result(
                    "POST_WRITE_MQTT_CONFIG_NOT_LOADED",
                    target_state=target,
                    publisher_node_id=post_publisher_id,
                    write_sent=write_sent,
                )
            try:
                post_loaded = bool(post_has_field("mqtt"))
            except Exception:
                post_loaded = False
            post_mqtt = getattr(post_module_config, "mqtt", None)
            if not post_loaded or post_mqtt is None:
                return self._publication_control_result(
                    "POST_WRITE_MQTT_CONFIG_NOT_LOADED",
                    target_state=target,
                    publisher_node_id=post_publisher_id,
                    write_sent=write_sent,
                )
            if bool(getattr(post_mqtt, "enabled", False)) != desired_enabled:
                return self._publication_control_result(
                    "POST_WRITE_TARGET_NOT_VERIFIED",
                    target_state=target,
                    publisher_node_id=post_publisher_id,
                    write_sent=write_sent,
                )
            if not self._publication_mqtt_non_target_equal(snapshot, post_mqtt):
                return self._publication_control_result(
                    "POST_WRITE_NON_TARGET_DELTA",
                    target_state=target,
                    publisher_node_id=post_publisher_id,
                    write_sent=write_sent,
                )

            self._publication_control_unverified = False
            return self._publication_control_result(
                "ACTIVATED_ON" if desired_enabled else "DEACTIVATED_OFF",
                state=target,
                target_state=target,
                publisher_node_id=post_publisher_id,
                write_sent=write_sent,
                verified=True,
            )
        except Exception:
            return self._publication_control_result(
                "CONTROL_INTERNAL_ERROR_UNKNOWN_STATE",
                target_state=target,
                publisher_node_id=publisher_node_id,
                write_sent=write_sent,
            )
        finally:
            snapshot = None
            self._publication_control_in_progress = False
            control_lock.release()

    def publication_transport_status(self, expected_node_id: str | None = None) -> dict[str, Any]:
        manager = getattr(self, "publication_transport_manager", None)
        if manager is None:
            return {
                "schema": "gutochat.map.publication.transport_status.v1",
                "state_fresh": False,
                "reason_code": "TRANSPORT_MANAGER_UNAVAILABLE",
                "read_source": "current_serial_interface_generation_attested_state",
            }
        return manager.status(expected_node_id)

    def publication_transport_authorization(
        self, target_transport: str, expected_node_id: str | None
    ) -> dict[str, Any]:
        manager = getattr(self, "publication_transport_manager", None)
        if manager is None:
            return {"authorized": False, "reason_code": "TRANSPORT_MANAGER_UNAVAILABLE"}
        return manager.authorization(target_transport, expected_node_id)

    def publication_transport_control(
        self, target_transport: str, *, authorization_token: str | None = None
    ) -> dict[str, Any]:
        manager = getattr(self, "publication_transport_manager", None)
        if manager is None:
            return {"result_code": "TRANSPORT_MANAGER_UNAVAILABLE", "verified": False}
        return manager.control(target_transport, authorization_token=authorization_token)

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
            elif command == "publication_status":
                response = {
                    "ok": True,
                    "publication_status": bridge.publication_status(
                        request.get("expected_node_id")
                    ),
                }
            elif command == "publication_transport_status":
                response = {
                    "ok": True,
                    "publication_transport_status": bridge.publication_transport_status(
                        request.get("expected_node_id")
                    ),
                }
            elif command == "publication_effective_status":
                response = {
                    "ok": True,
                    "publication_effective_status": bridge.remote_publication_status(),
                }
            elif command in {
                "publication_authorization",
                "publication_control",
                "publication_transport_authorization",
                "publication_transport_control",
            }:
                # MAP-PUB-A1-14-P1.2: privileged publication writes are not
                # reachable through the generic loopback TCP API.  They must
                # use the OS-permission-protected AF_UNIX control channel.
                response = {
                    "ok": False,
                    "error": "PRIVILEGED_LOCAL_CHANNEL_REQUIRED",
                }
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


def _publication_control_peer_credentials(sock: socket.socket) -> tuple[int, int, int] | None:
    """Return Linux AF_UNIX (pid, uid, gid) credentials or fail closed."""
    if not hasattr(socket, "SO_PEERCRED"):
        return None
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
        return int(pid), int(uid), int(gid)
    except (OSError, struct.error):
        return None


def _prepare_publication_control_socket(path: Path) -> None:
    """Create a private parent and safely remove only our stale socket."""
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_stat = parent.stat()
    if parent_stat.st_uid != os.getuid():
        raise RuntimeError("publication control directory owner mismatch")
    if stat.S_IMODE(parent_stat.st_mode) != 0o700:
        os.chmod(parent, 0o700)
    if path.exists() or path.is_symlink():
        entry = path.lstat()
        if stat.S_ISLNK(entry.st_mode) or not stat.S_ISSOCK(entry.st_mode):
            raise RuntimeError("publication control path exists and is not a socket")
        if entry.st_uid != os.getuid():
            raise RuntimeError("publication control socket owner mismatch")
        path.unlink()


class PublicationControlUnixHandler(socketserver.StreamRequestHandler):
    """Privileged MAP-PUB commands; intentionally excludes read-only API calls."""

    def handle(self) -> None:
        bridge: MeshBridge = self.server.bridge  # type: ignore[attr-defined]
        try:
            request = json.loads(self.rfile.readline(1024 * 1024).decode("utf-8"))
            command = request.get("command")
            if command == "publication_authorization":
                response = {
                    "ok": True,
                    "publication_authorization": bridge.publication_authorization(
                        request.get("target_state"),
                        request.get("expected_node_id"),
                    ),
                }
            elif command == "publication_control":
                response = {
                    "ok": True,
                    "publication_control": bridge.publication_control(
                        request.get("target_state"),
                        authorization_token=request.get("authorization_token"),
                    ),
                }
            elif command == "publication_effective_authorization":
                response = {
                    "ok": True,
                    "publication_effective_authorization": bridge.effective_publication_authorization(
                        request.get("target_state"),
                        request.get("expected_node_id"),
                    ),
                }
            elif command == "publication_effective_control":
                response = {
                    "ok": True,
                    "publication_effective_control": bridge.effective_publication_control(
                        request.get("target_state"),
                        authorization_token=request.get("authorization_token"),
                    ),
                }
            elif command == "publication_transport_authorization":
                response = {
                    "ok": True,
                    "publication_transport_authorization": bridge.publication_transport_authorization(
                        request.get("target_transport"),
                        request.get("expected_node_id"),
                    ),
                }
            elif command == "publication_transport_control":
                response = {
                    "ok": True,
                    "publication_transport_control": bridge.publication_transport_control(
                        request.get("target_transport"),
                        authorization_token=request.get("authorization_token"),
                    ),
                }
            else:
                response = {"ok": False, "error": "PRIVILEGED_COMMAND_REQUIRED"}
        except Exception as exc:
            response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        self.wfile.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))


class PublicationControlUnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path: Path, handler: type[socketserver.StreamRequestHandler]) -> None:
        self.control_path = path
        self.allowed_uids = {0, os.getuid()}
        _prepare_publication_control_socket(path)
        try:
            super().__init__(str(path), handler)
            os.chmod(path, 0o600)
        except Exception:
            try:
                if path.exists() and stat.S_ISSOCK(path.lstat().st_mode):
                    path.unlink()
            except OSError:
                pass
            raise

    def verify_request(self, request: Any, client_address: Any) -> bool:
        credentials = _publication_control_peer_credentials(request)
        if credentials is None:
            LOG.warning("Avviser MAP-PUB control peer uten SO_PEERCRED")
            return False
        pid, uid, _gid = credentials
        allowed = uid in self.allowed_uids
        if not allowed:
            LOG.warning("Avviser MAP-PUB control peer pid=%s uid=%s", pid, uid)
        return allowed

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            try:
                if self.control_path.exists() and stat.S_ISSOCK(
                    self.control_path.lstat().st_mode
                ):
                    self.control_path.unlink()
            except OSError:
                pass


def _start_publication_control_server(
    bridge: MeshBridge, config: dict[str, Any], enabled: bool
) -> tuple[PublicationControlUnixServer | None, threading.Thread | None, Path | None]:
    """Start the privileged MAP-PUB channel only when explicitly opted in.

    The default is deliberately disabled because this module is shared by the
    868, 433 and 433F meshbridge services. Disabled instances must not inspect,
    create, unlink or otherwise touch the MAP-PUB control socket path.
    """
    if not enabled:
        return None, None, None

    control_path = Path(
        str(config.get("map_publication_control_socket", MAP_PUBLICATION_CONTROL_SOCKET_DEFAULT))
    ).expanduser()
    control_server = PublicationControlUnixServer(
        control_path, PublicationControlUnixHandler
    )
    control_server.bridge = bridge  # type: ignore[attr-defined]
    control_thread = threading.Thread(
        target=control_server.serve_forever,
        kwargs={"poll_interval": 0.5},
        name="map-pub-control",
        daemon=True,
    )
    control_thread.start()
    return control_server, control_thread, control_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument(
        "--enable-map-publication-control",
        action="store_true",
        help=(
            "Enable the privileged MAP-PUB AF_UNIX control channel. "
            "Fail-closed default is disabled for shared 433/433F instances."
        ),
    )
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    from hardware_profile_runtime import load_runtime_config

    config = load_runtime_config(Path(args.config))
    from field_base_parity_policy import apply_field_base_parity_policy
    config = apply_field_base_parity_policy(config)
    bridge = MeshBridge(config)
    bridge.start()
    server = ApiServer((bridge.api_host, bridge.api_port), ApiHandler)
    server.bridge = bridge  # type: ignore[attr-defined]
    control_server, control_thread, control_path = _start_publication_control_server(
        bridge, config, args.enable_map_publication_control
    )

    def request_stop(signum: int, frame: Any) -> None:
        LOG.info("Stoppsignal mottatt")
        bridge.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()
        if control_server is not None:
            threading.Thread(target=control_server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    LOG.info("Meshtastic API lytter på %s:%s", bridge.api_host, bridge.api_port)
    if control_path is None:
        LOG.info("MAP-PUB kontrollkanal er deaktivert for denne instansen")
    else:
        LOG.info("MAP-PUB kontrollkanal lytter på %s", control_path)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        bridge.stop()
        if control_server is not None:
            control_server.shutdown()
        if control_thread is not None:
            control_thread.join(timeout=2.0)
        if control_server is not None:
            control_server.server_close()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
