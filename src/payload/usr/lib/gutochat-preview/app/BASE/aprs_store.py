#!/usr/bin/env python3
"""Durable, transport-independent APRS position/weather storage for GuToMap."""
from __future__ import annotations

import hashlib
from contextlib import closing
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from aprs_model import AprsPacket


STORE_RESULTS = {"created", "updated", "duplicate", "older", "ignored"}

A2_RECEIPT_KEY_SCHEMA = "gutchat.aprs.receipt.key.v1"
A2_RECEIPT_STATES = {
    "received",
    "domain_persisted",
    "domain_rejected",
}
A2_RECEIPT_DOMAIN_SUCCESS_RESULTS = {
    "created",
    "updated",
    "duplicate",
    "older",
}

_POSITION_EXTRA_COLUMNS: tuple[tuple[str, str], ...] = (
    ("position_format", "TEXT NOT NULL DEFAULT 'uncompressed'"),
    ("wind_direction_deg", "INTEGER"),
    ("wind_speed_kmh", "REAL"),
    ("gust_kmh", "REAL"),
    ("temperature_c", "REAL"),
    ("rain_last_hour_mm", "REAL"),
    ("rain_last_24h_mm", "REAL"),
    ("rain_since_midnight_mm", "REAL"),
    ("humidity_percent", "INTEGER"),
    ("pressure_hpa", "REAL"),
)


class AprsStore:
    """Store APRS station presence and position history in dedicated tables."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=5000")
        return con

    @staticmethod
    def _ensure_columns(
        con: sqlite3.Connection,
        table: str,
        columns: tuple[tuple[str, str], ...],
    ) -> None:
        existing = {
            str(row[1])
            for row in con.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for name, declaration in columns:
            if name not in existing:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

    def _init_db(self) -> None:
        with closing(self._connect()) as con, con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS aprs_stations (
                    station_id TEXT PRIMARY KEY,
                    callsign TEXT NOT NULL,
                    ssid INTEGER,
                    last_received_at TEXT NOT NULL,
                    last_received_epoch INTEGER NOT NULL,
                    source_type TEXT NOT NULL,
                    transport TEXT NOT NULL,
                    source_gateway TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS aprs_positions_latest (
                    station_id TEXT PRIMARY KEY,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    altitude_m REAL,
                    course_deg INTEGER,
                    speed_kmh REAL,
                    symbol_table TEXT NOT NULL,
                    symbol_code TEXT NOT NULL,
                    packet_time_raw TEXT,
                    received_at TEXT NOT NULL,
                    received_epoch INTEGER NOT NULL,
                    source_type TEXT NOT NULL,
                    transport TEXT NOT NULL,
                    source_gateway TEXT NOT NULL DEFAULT '',
                    packet_path TEXT NOT NULL DEFAULT '[]',
                    comment TEXT NOT NULL DEFAULT '',
                    raw_packet_hash TEXT NOT NULL,
                    observation_key TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    position_format TEXT NOT NULL DEFAULT 'uncompressed',
                    wind_direction_deg INTEGER,
                    wind_speed_kmh REAL,
                    gust_kmh REAL,
                    temperature_c REAL,
                    rain_last_hour_mm REAL,
                    rain_last_24h_mm REAL,
                    rain_since_midnight_mm REAL,
                    humidity_percent INTEGER,
                    pressure_hpa REAL
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS aprs_positions_history (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    station_id TEXT NOT NULL,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    altitude_m REAL,
                    course_deg INTEGER,
                    speed_kmh REAL,
                    symbol_table TEXT NOT NULL,
                    symbol_code TEXT NOT NULL,
                    packet_time_raw TEXT,
                    received_at TEXT NOT NULL,
                    received_epoch INTEGER NOT NULL,
                    source_type TEXT NOT NULL,
                    transport TEXT NOT NULL,
                    source_gateway TEXT NOT NULL DEFAULT '',
                    packet_path TEXT NOT NULL DEFAULT '[]',
                    comment TEXT NOT NULL DEFAULT '',
                    raw_packet_hash TEXT NOT NULL,
                    observation_key TEXT NOT NULL UNIQUE,
                    stored_at TEXT NOT NULL,
                    position_format TEXT NOT NULL DEFAULT 'uncompressed',
                    wind_direction_deg INTEGER,
                    wind_speed_kmh REAL,
                    gust_kmh REAL,
                    temperature_c REAL,
                    rain_last_hour_mm REAL,
                    rain_last_24h_mm REAL,
                    rain_since_midnight_mm REAL,
                    humidity_percent INTEGER,
                    pressure_hpa REAL
                )
                """
            )
            # A1.4 must also upgrade an existing A1.0/A1.1/A1.2 local database
            # without dropping or rewriting APRS history.
            self._ensure_columns(con, "aprs_positions_latest", _POSITION_EXTRA_COLUMNS)
            self._ensure_columns(con, "aprs_positions_history", _POSITION_EXTRA_COLUMNS)
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_aprs_history_station_epoch "
                "ON aprs_positions_history(station_id, received_epoch)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_aprs_latest_received_epoch "
                "ON aprs_positions_latest(received_epoch)"
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS aprs_receipts (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_key TEXT NOT NULL UNIQUE,
                    event_schema TEXT NOT NULL,
                    network TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    receiver_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    received_epoch INTEGER NOT NULL,
                    raw_tnc2 TEXT NOT NULL,
                    raw_tnc2_hash TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    processing_state TEXT NOT NULL
                        CHECK(processing_state IN (
                            'received',
                            'domain_persisted',
                            'domain_rejected'
                        )),
                    observation_key TEXT,
                    domain_store_result TEXT,
                    last_error_code TEXT NOT NULL DEFAULT ''
                )
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_aprs_receipts_receiver_epoch "
                "ON aprs_receipts(receiver_id, received_epoch)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_aprs_receipts_observation_key "
                "ON aprs_receipts(observation_key)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_aprs_receipts_state "
                "ON aprs_receipts(processing_state)"
            )

    @staticmethod
    def _a2_receipt_material(
        event: dict[str, Any],
        receiver_id: str,
    ) -> dict[str, Any]:
        if not isinstance(event, dict):
            raise ValueError("A2 receipt event must be a dictionary")

        receiver = str(receiver_id).strip()
        if not receiver:
            raise ValueError("A2 receipt receiver_id must be non-empty")

        event_schema = event.get("schema")
        network = event.get("network")
        direction = event.get("direction")

        if (
            event_schema != "gutchat.aprs.rx.v1"
            or network != "classic_aprs_rf"
            or direction != "rx"
        ):
            raise ValueError("Invalid A2 receipt event contract")

        raw_tnc2 = event.get("raw_tnc2")
        received_at = event.get("received_at")

        if not isinstance(raw_tnc2, str) or not raw_tnc2.strip():
            raise ValueError("A2 receipt raw_tnc2 must be non-empty")
        if "\r" in raw_tnc2 or "\n" in raw_tnc2:
            raise ValueError("A2 receipt raw_tnc2 must be one logical line")
        if not isinstance(received_at, str) or not received_at:
            raise ValueError("A2 receipt received_at must be non-empty")

        try:
            parsed = datetime.fromisoformat(received_at)
        except ValueError as exc:
            raise ValueError("A2 receipt received_at must be ISO-8601") from exc

        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError(
                "A2 receipt received_at must include a timezone offset"
            )

        try:
            event_json = json.dumps(
                event,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            identity_json = json.dumps(
                {
                    "receipt_key_schema": A2_RECEIPT_KEY_SCHEMA,
                    "receiver_id": receiver,
                    "event": event,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "A2 receipt event must be canonical JSON"
            ) from exc

        event_hash = hashlib.sha256(
            event_json.encode("utf-8", "strict")
        ).hexdigest()

        receipt_key = hashlib.sha256(
            identity_json.encode("utf-8", "strict")
        ).hexdigest()

        raw_tnc2_hash = hashlib.sha256(
            raw_tnc2.encode("utf-8", "strict")
        ).hexdigest()

        return {
            "receipt_key": receipt_key,
            "event_schema": event_schema,
            "network": network,
            "direction": direction,
            "receiver_id": receiver,
            "received_at": received_at,
            "received_epoch": int(parsed.timestamp()),
            "raw_tnc2": raw_tnc2,
            "raw_tnc2_hash": raw_tnc2_hash,
            "event_json": event_json,
            "event_hash": event_hash,
        }

    def begin_a2_receipt(
        self,
        event: dict[str, Any],
        receiver_id: str,
    ) -> dict[str, Any]:
        """Durably create or load one idempotent A2 receipt."""
        material = self._a2_receipt_material(
            event,
            receiver_id,
        )
        receipt_key = str(material["receipt_key"])

        with closing(self._connect()) as con, con:
            con.execute("BEGIN IMMEDIATE")

            existing = con.execute(
                "SELECT * FROM aprs_receipts WHERE receipt_key = ?",
                (receipt_key,),
            ).fetchone()

            if existing is not None:
                result = self._row_to_dict(existing)
                assert result is not None
                result["receipt_store_result"] = "duplicate"
                return result

            con.execute(
                """
                INSERT INTO aprs_receipts(
                    receipt_key,
                    event_schema,
                    network,
                    direction,
                    receiver_id,
                    received_at,
                    received_epoch,
                    raw_tnc2,
                    raw_tnc2_hash,
                    event_json,
                    event_hash,
                    processing_state,
                    last_error_code
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'received', ''
                )
                """,
                (
                    material["receipt_key"],
                    material["event_schema"],
                    material["network"],
                    material["direction"],
                    material["receiver_id"],
                    material["received_at"],
                    material["received_epoch"],
                    material["raw_tnc2"],
                    material["raw_tnc2_hash"],
                    material["event_json"],
                    material["event_hash"],
                ),
            )

            created = con.execute(
                "SELECT * FROM aprs_receipts WHERE receipt_key = ?",
                (receipt_key,),
            ).fetchone()

            result = self._row_to_dict(created)
            assert result is not None
            result["receipt_store_result"] = "created"
            return result

    def get_a2_receipt(
        self,
        receipt_key: str,
    ) -> dict[str, Any] | None:
        key = str(receipt_key).strip()
        if not key:
            raise ValueError("A2 receipt_key must be non-empty")

        with closing(self._connect()) as con, con:
            return self._row_to_dict(
                con.execute(
                    "SELECT * FROM aprs_receipts WHERE receipt_key = ?",
                    (key,),
                ).fetchone()
            )

    def finalize_a2_receipt(
        self,
        receipt_key: str,
        *,
        processing_state: str,
        observation_key: str | None,
        domain_store_result: str | None,
        last_error_code: str,
    ) -> str:
        """Finalize one received receipt without changing domain semantics."""
        key = str(receipt_key).strip()
        state = str(processing_state).strip()
        error = str(last_error_code or "").strip()

        if not key:
            raise ValueError("A2 receipt_key must be non-empty")

        if state not in {
            "domain_persisted",
            "domain_rejected",
        }:
            raise ValueError("A2 receipt final state is invalid")

        observation = (
            None
            if observation_key is None
            else str(observation_key).strip()
        )

        domain_result = (
            None
            if domain_store_result is None
            else str(domain_store_result).strip()
        )

        if state == "domain_persisted":
            if domain_result not in A2_RECEIPT_DOMAIN_SUCCESS_RESULTS:
                raise ValueError(
                    "Persisted A2 receipt requires a successful domain result"
                )
            if not observation:
                raise ValueError(
                    "Persisted A2 receipt requires observation_key"
                )
            if error:
                raise ValueError(
                    "Persisted A2 receipt must not have an error code"
                )
        else:
            if domain_result not in {None, "ignored"}:
                raise ValueError(
                    "Rejected A2 receipt has invalid domain result"
                )
            if not error:
                raise ValueError(
                    "Rejected A2 receipt requires an error code"
                )

        with closing(self._connect()) as con, con:
            con.execute("BEGIN IMMEDIATE")

            current = con.execute(
                """
                SELECT
                    processing_state,
                    observation_key,
                    domain_store_result,
                    last_error_code
                FROM aprs_receipts
                WHERE receipt_key = ?
                """,
                (key,),
            ).fetchone()

            if current is None:
                raise ValueError("Unknown A2 receipt_key")

            current_state = str(current["processing_state"])

            if current_state != "received":
                same = (
                    current_state == state
                    and current["observation_key"] == observation
                    and current["domain_store_result"] == domain_result
                    and str(current["last_error_code"]) == error
                )

                if same:
                    return "duplicate"

                raise ValueError(
                    "A2 receipt final state conflicts with existing result"
                )

            con.execute(
                """
                UPDATE aprs_receipts
                SET
                    processing_state = ?,
                    observation_key = ?,
                    domain_store_result = ?,
                    last_error_code = ?
                WHERE receipt_key = ?
                """,
                (
                    state,
                    observation,
                    domain_result,
                    error,
                    key,
                ),
            )

            return "updated"

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        if "packet_path" in result:
            try:
                result["packet_path"] = json.loads(result["packet_path"])
            except (TypeError, json.JSONDecodeError):
                result["packet_path"] = []
        return result

    @staticmethod
    def _weather_values(packet: AprsPacket) -> tuple[Any, ...]:
        assert packet.position is not None
        weather = packet.position.weather
        if weather is None:
            return (None,) * 9
        return (
            weather.wind_direction_deg,
            weather.wind_speed_kmh,
            weather.gust_kmh,
            weather.temperature_c,
            weather.rain_last_hour_mm,
            weather.rain_last_24h_mm,
            weather.rain_since_midnight_mm,
            weather.humidity_percent,
            weather.pressure_hpa,
        )

    def store_packet(self, packet: AprsPacket) -> str:
        """Persist one normalized APRS position/weather packet."""
        if packet.parse_state != "position" or packet.position is None:
            return "ignored"

        pos = packet.position
        path_json = json.dumps(list(packet.path), ensure_ascii=True, separators=(",", ":"))
        weather_values = self._weather_values(packet)

        with closing(self._connect()) as con, con:
            con.execute("BEGIN IMMEDIATE")
            latest = con.execute(
                "SELECT received_epoch, observation_key FROM aprs_positions_latest "
                "WHERE station_id = ?",
                (packet.station_id,),
            ).fetchone()

            existing_history = con.execute(
                "SELECT 1 FROM aprs_positions_history WHERE observation_key = ?",
                (packet.observation_key,),
            ).fetchone()

            if existing_history is None:
                con.execute(
                    """
                    INSERT INTO aprs_positions_history(
                        station_id, latitude, longitude, altitude_m, course_deg,
                        speed_kmh, symbol_table, symbol_code, packet_time_raw,
                        received_at, received_epoch, source_type, transport,
                        source_gateway, packet_path, comment, raw_packet_hash,
                        observation_key, stored_at, position_format,
                        wind_direction_deg, wind_speed_kmh, gust_kmh,
                        temperature_c, rain_last_hour_mm, rain_last_24h_mm,
                        rain_since_midnight_mm, humidity_percent, pressure_hpa
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        packet.station_id,
                        float(pos.latitude),
                        float(pos.longitude),
                        pos.altitude_m,
                        pos.course_deg,
                        pos.speed_kmh,
                        pos.symbol_table,
                        pos.symbol_code,
                        pos.packet_time_raw,
                        packet.received_at,
                        int(packet.received_epoch),
                        packet.source_type,
                        packet.transport,
                        packet.source_gateway,
                        path_json,
                        pos.comment,
                        packet.raw_packet_hash,
                        packet.observation_key,
                        packet.received_at,
                        pos.position_format,
                        *weather_values,
                    ),
                )

            is_older = latest is not None and int(packet.received_epoch) < int(latest["received_epoch"])
            is_duplicate = existing_history is not None

            station = con.execute(
                "SELECT last_received_epoch FROM aprs_stations WHERE station_id = ?",
                (packet.station_id,),
            ).fetchone()
            if station is None or int(packet.received_epoch) >= int(station["last_received_epoch"]):
                con.execute(
                    """
                    INSERT INTO aprs_stations(
                        station_id, callsign, ssid, last_received_at,
                        last_received_epoch, source_type, transport,
                        source_gateway, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(station_id) DO UPDATE SET
                        callsign=excluded.callsign,
                        ssid=excluded.ssid,
                        last_received_at=excluded.last_received_at,
                        last_received_epoch=excluded.last_received_epoch,
                        source_type=excluded.source_type,
                        transport=excluded.transport,
                        source_gateway=excluded.source_gateway,
                        updated_at=excluded.updated_at
                    """,
                    (
                        packet.station_id,
                        packet.callsign,
                        packet.ssid,
                        packet.received_at,
                        int(packet.received_epoch),
                        packet.source_type,
                        packet.transport,
                        packet.source_gateway,
                        packet.received_at,
                    ),
                )

            if is_older:
                return "duplicate" if is_duplicate else "older"

            con.execute(
                """
                INSERT INTO aprs_positions_latest(
                    station_id, latitude, longitude, altitude_m, course_deg,
                    speed_kmh, symbol_table, symbol_code, packet_time_raw,
                    received_at, received_epoch, source_type, transport,
                    source_gateway, packet_path, comment, raw_packet_hash,
                    observation_key, updated_at, position_format,
                    wind_direction_deg, wind_speed_kmh, gust_kmh,
                    temperature_c, rain_last_hour_mm, rain_last_24h_mm,
                    rain_since_midnight_mm, humidity_percent, pressure_hpa
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT(station_id) DO UPDATE SET
                    latitude=excluded.latitude,
                    longitude=excluded.longitude,
                    altitude_m=excluded.altitude_m,
                    course_deg=excluded.course_deg,
                    speed_kmh=excluded.speed_kmh,
                    symbol_table=excluded.symbol_table,
                    symbol_code=excluded.symbol_code,
                    packet_time_raw=excluded.packet_time_raw,
                    received_at=excluded.received_at,
                    received_epoch=excluded.received_epoch,
                    source_type=excluded.source_type,
                    transport=excluded.transport,
                    source_gateway=excluded.source_gateway,
                    packet_path=excluded.packet_path,
                    comment=excluded.comment,
                    raw_packet_hash=excluded.raw_packet_hash,
                    observation_key=excluded.observation_key,
                    updated_at=excluded.updated_at,
                    position_format=excluded.position_format,
                    wind_direction_deg=excluded.wind_direction_deg,
                    wind_speed_kmh=excluded.wind_speed_kmh,
                    gust_kmh=excluded.gust_kmh,
                    temperature_c=excluded.temperature_c,
                    rain_last_hour_mm=excluded.rain_last_hour_mm,
                    rain_last_24h_mm=excluded.rain_last_24h_mm,
                    rain_since_midnight_mm=excluded.rain_since_midnight_mm,
                    humidity_percent=excluded.humidity_percent,
                    pressure_hpa=excluded.pressure_hpa
                """,
                (
                    packet.station_id,
                    float(pos.latitude),
                    float(pos.longitude),
                    pos.altitude_m,
                    pos.course_deg,
                    pos.speed_kmh,
                    pos.symbol_table,
                    pos.symbol_code,
                    pos.packet_time_raw,
                    packet.received_at,
                    int(packet.received_epoch),
                    packet.source_type,
                    packet.transport,
                    packet.source_gateway,
                    path_json,
                    pos.comment,
                    packet.raw_packet_hash,
                    packet.observation_key,
                    packet.received_at,
                    pos.position_format,
                    *weather_values,
                ),
            )

            if latest is None:
                return "created"
            if is_duplicate:
                return "duplicate"
            return "updated"

    def get_latest(self, station_id: str) -> dict[str, Any] | None:
        from aprs_model import canonical_station_id

        canonical, _, _ = canonical_station_id(station_id)
        with closing(self._connect()) as con, con:
            row = con.execute(
                "SELECT * FROM aprs_positions_latest WHERE station_id = ?",
                (canonical,),
            ).fetchone()
        return self._row_to_dict(row)

    def list_latest(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        count = int(limit)
        if not 1 <= count <= 100_000:
            raise ValueError("APRS latest limit must be in the range 1..100000")
        with closing(self._connect()) as con, con:
            rows = con.execute(
                "SELECT * FROM aprs_positions_latest "
                "ORDER BY received_epoch DESC, station_id ASC LIMIT ?",
                (count,),
            ).fetchall()
        return [self._row_to_dict(row) or {} for row in rows]

    def list_history(
        self,
        station_id: str | None = None,
        *,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        count = int(limit)
        if not 1 <= count <= 100_000:
            raise ValueError("APRS history limit must be in the range 1..100000")
        with closing(self._connect()) as con, con:
            if station_id is None:
                rows = con.execute(
                    "SELECT * FROM aprs_positions_history "
                    "ORDER BY sequence DESC LIMIT ?",
                    (count,),
                ).fetchall()
            else:
                from aprs_model import canonical_station_id

                canonical, _, _ = canonical_station_id(station_id)
                rows = con.execute(
                    "SELECT * FROM aprs_positions_history WHERE station_id = ? "
                    "ORDER BY sequence DESC LIMIT ?",
                    (canonical, count),
                ).fetchall()
        return [self._row_to_dict(row) or {} for row in rows]

    def history_count(self, station_id: str | None = None) -> int:
        with closing(self._connect()) as con, con:
            if station_id is None:
                return int(con.execute("SELECT COUNT(*) FROM aprs_positions_history").fetchone()[0])
            from aprs_model import canonical_station_id

            canonical, _, _ = canonical_station_id(station_id)
            return int(
                con.execute(
                    "SELECT COUNT(*) FROM aprs_positions_history WHERE station_id = ?",
                    (canonical,),
                ).fetchone()[0]
            )
