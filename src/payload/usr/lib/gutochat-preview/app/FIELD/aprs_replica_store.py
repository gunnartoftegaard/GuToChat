#!/usr/bin/env python3
"""Dedicated Field-side APRS presentation replica.

This store is intentionally independent from APRS receive/iGate components.
Only validated Base presentation observations are accepted.  The remote cursor
moves only after a complete batch is committed.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

REPLICA_SCHEMA = "gutochat.aprs.presentation.replica.v1"
SYNC_SOURCE_TYPE = "local_rf"
SYNC_TRANSPORT = "vhf_ax25"

_COLUMNS = (
    "station_id", "latitude", "longitude", "altitude_m", "course_deg",
    "speed_kmh", "symbol_table", "symbol_code", "packet_time_raw",
    "received_at", "received_epoch", "source_type", "transport",
    "source_gateway", "packet_path", "comment", "observation_key",
    "position_format", "wind_direction_deg", "wind_speed_kmh", "gust_kmh",
    "temperature_c", "rain_last_hour_mm", "rain_last_24h_mm",
    "rain_since_midnight_mm", "humidity_percent", "pressure_hpa",
)


class AprsReplicaStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.database_path, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=5000")
        return con

    def _init_db(self) -> None:
        with self._connect() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS aprs_replica_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS aprs_positions_history (
                    sequence INTEGER PRIMARY KEY,
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
                    raw_packet_hash TEXT NOT NULL DEFAULT '',
                    observation_key TEXT NOT NULL UNIQUE,
                    stored_at TEXT NOT NULL DEFAULT '',
                    ingested_epoch INTEGER,
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
                );
                CREATE INDEX IF NOT EXISTS idx_aprs_replica_history_retention_ingested_epoch
                    ON aprs_positions_history(ingested_epoch, sequence);
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
                    raw_packet_hash TEXT NOT NULL DEFAULT '',
                    observation_key TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT '',
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
                );
                """
            )
            con.execute(
                "INSERT OR IGNORE INTO aprs_replica_state(key,value) VALUES('schema',?)",
                (REPLICA_SCHEMA,),
            )
            con.execute(
                "INSERT OR IGNORE INTO aprs_replica_state(key,value) VALUES('remote_cursor','0')"
            )

    def remote_cursor(self) -> int:
        with self._connect() as con:
            row = con.execute(
                "SELECT value FROM aprs_replica_state WHERE key='remote_cursor'"
            ).fetchone()
        return int(row[0]) if row else 0

    @staticmethod
    def _validate_payload(payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("APRS_REPLICA_PAYLOAD_NOT_OBJECT")
        station = str(payload.get("station_id") or "").strip().upper()
        obs = str(payload.get("observation_key") or "").strip()
        if not station or len(station) > 20 or not obs or len(obs) > 128:
            raise ValueError("APRS_REPLICA_ID_INVALID")
        try:
            lat = float(payload["latitude"])
            lon = float(payload["longitude"])
            epoch = int(payload["received_epoch"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("APRS_REPLICA_POSITION_INVALID") from exc
        if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0 and epoch >= 0):
            raise ValueError("APRS_REPLICA_POSITION_INVALID")
        packet_path = payload.get("packet_path", "[]")
        if isinstance(packet_path, list):
            packet_path = json.dumps(packet_path, ensure_ascii=False, separators=(",", ":"))
        else:
            try:
                parsed = json.loads(str(packet_path or "[]"))
                if not isinstance(parsed, list):
                    raise ValueError
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError("APRS_REPLICA_PATH_INVALID") from exc
            packet_path = json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
        result = {name: payload.get(name) for name in _COLUMNS}
        result.update({"station_id": station, "observation_key": obs,
                       "latitude": lat, "longitude": lon,
                       "received_epoch": epoch, "packet_path": packet_path})
        result["symbol_table"] = str(result.get("symbol_table") or "/")[:1]
        result["symbol_code"] = str(result.get("symbol_code") or ">")[:1]
        result["received_at"] = str(result.get("received_at") or "")
        result["source_type"] = str(result.get("source_type") or "")
        result["transport"] = str(result.get("transport") or "")
        if result["source_type"] != SYNC_SOURCE_TYPE:
            raise ValueError("APRS_REPLICA_SOURCE_NOT_ALLOWED")
        if result["transport"] != SYNC_TRANSPORT:
            raise ValueError("APRS_REPLICA_TRANSPORT_NOT_ALLOWED")
        result["source_gateway"] = str(result.get("source_gateway") or "")
        result["comment"] = str(result.get("comment") or "")[:512]
        result["position_format"] = str(result.get("position_format") or "uncompressed")[:32]
        return result

    def apply_snapshot(
        self,
        *,
        observations: list[tuple[int, dict[str, Any]]],
        baseline_sequence: int,
    ) -> int:
        """Atomically install one complete latest snapshot and advance to its baseline."""
        if self.remote_cursor() != 0:
            raise ValueError("APRS_REPLICA_SNAPSHOT_REQUIRES_ZERO_CURSOR")
        baseline = max(0, int(baseline_sequence))
        cursor = 0
        validated: list[tuple[int, dict[str, Any]]] = []
        for sequence, payload in observations:
            seq = int(sequence)
            if seq <= cursor or seq > baseline:
                raise ValueError("APRS_REPLICA_SNAPSHOT_SEQUENCE_INVALID")
            cursor = seq
            validated.append((seq, self._validate_payload(payload)))
        columns = ",".join(_COLUMNS)
        placeholders = ",".join("?" for _ in _COLUMNS)
        update_cols = ",".join(
            f"{name}=excluded.{name}" for name in _COLUMNS if name != "station_id"
        )
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            for seq, item in validated:
                values = tuple(item[name] for name in _COLUMNS)
                ingested_epoch = int(time.time())
                con.execute(
                    f"INSERT OR IGNORE INTO aprs_positions_history(sequence,{columns},ingested_epoch) "
                    f"VALUES(?,{placeholders},?)",
                    (seq, *values, ingested_epoch),
                )
                con.execute(
                    f"INSERT INTO aprs_positions_latest({columns}) VALUES({placeholders}) "
                    f"ON CONFLICT(station_id) DO UPDATE SET {update_cols}",
                    values,
                )
            con.execute(
                "INSERT INTO aprs_replica_state(key,value) VALUES('remote_cursor',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(baseline),),
            )
        return baseline

    def apply_batch(
        self,
        *,
        start_cursor: int,
        observations: list[tuple[int, dict[str, Any]]],
        final_cursor: int,
    ) -> int:
        expected = self.remote_cursor()
        if int(start_cursor) != expected:
            raise ValueError("APRS_REPLICA_CURSOR_MISMATCH")
        cursor = expected
        validated: list[tuple[int, dict[str, Any]]] = []
        for sequence, payload in observations:
            seq = int(sequence)
            if seq <= cursor:
                raise ValueError("APRS_REPLICA_SEQUENCE_NOT_INCREASING")
            cursor = seq
            validated.append((seq, self._validate_payload(payload)))
        final = int(final_cursor)
        if final < expected:
            raise ValueError("APRS_REPLICA_CURSOR_ROLLBACK")
        if validated and final < cursor:
            raise ValueError("APRS_REPLICA_FINAL_CURSOR_BEHIND_OBSERVATION")
        columns = ",".join(_COLUMNS)
        placeholders = ",".join("?" for _ in _COLUMNS)
        update_cols = ",".join(f"{name}=excluded.{name}" for name in _COLUMNS if name != "station_id")
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            for seq, item in validated:
                values = tuple(item[name] for name in _COLUMNS)
                ingested_epoch = int(time.time())
                con.execute(
                    f"INSERT OR IGNORE INTO aprs_positions_history(sequence,{columns},ingested_epoch) "
                    f"VALUES(?,{placeholders},?)",
                    (seq, *values, ingested_epoch),
                )
                current = con.execute(
                    "SELECT received_epoch FROM aprs_positions_latest WHERE station_id=?",
                    (item["station_id"],),
                ).fetchone()
                if current is None or int(item["received_epoch"]) >= int(current[0]):
                    con.execute(
                        f"INSERT INTO aprs_positions_latest({columns}) VALUES({placeholders}) "
                        f"ON CONFLICT(station_id) DO UPDATE SET {update_cols}",
                        values,
                    )
            con.execute(
                "INSERT INTO aprs_replica_state(key,value) VALUES('remote_cursor',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(int(final_cursor)),),
            )
        return int(final_cursor)
