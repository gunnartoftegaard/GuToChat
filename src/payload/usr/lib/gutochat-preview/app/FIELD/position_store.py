#!/usr/bin/env python3
"""Durable latest-position and position-history storage for Meshtastic."""
from __future__ import annotations

from contextlib import contextmanager

import hashlib
import json
import math
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping


DEFAULT_STALE_MINUTES = 30
MAX_STALE_MINUTES = 365 * 24 * 60
MAX_EXPORT_HISTORY_ROWS = 100_000
POSITION_RESULTS = {
    "created",
    "updated",
    "duplicate",
    "older",
    "invalid",
    "suspicious",
    "disabled",
}
LOCATION_SOURCE_VALUES = {
    "LOC_UNSET": 0,
    "LOC_MANUAL": 1,
    "LOC_INTERNAL": 2,
    "LOC_EXTERNAL": 3,
}
ALTITUDE_SOURCE_VALUES = {
    "ALT_UNSET": 0,
    "ALT_MANUAL": 1,
    "ALT_INTERNAL": 2,
    "ALT_EXTERNAL": 3,
    "ALT_BAROMETRIC": 4,
}


def is_suspicious_precision_midpoint(
    latitude_i: Any,
    longitude_i: Any,
    precision_bits: Any,
) -> bool:
    """Return true for the known zero-near precision midpoint signature.

    A malformed privacy-reduced Meshtastic position observed in production had
    both coordinates set to exactly ``1 << (31 - precision_bits)``.  The
    signature is deliberately narrow so ordinary reduced-precision positions,
    including valid 13-bit fixes, remain accepted.
    """
    if any(isinstance(value, bool) for value in (
        latitude_i, longitude_i, precision_bits
    )):
        return False
    try:
        latitude = int(latitude_i)
        longitude = int(longitude_i)
        precision = int(precision_bits)
    except (TypeError, ValueError, OverflowError):
        return False
    if not 1 <= precision < 32:
        return False
    midpoint = 1 << (31 - precision)
    return latitude == midpoint and longitude == midpoint


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def canonical_node_id(value: Any, num: Any = None) -> tuple[str, int]:
    """Return canonical ``!xxxxxxxx`` node ID and its unsigned 32-bit number."""
    text = str(value or "").strip().lower()
    if not text and num not in (None, ""):
        try:
            numeric = int(num)
        except (TypeError, ValueError) as exc:
            raise ValueError("Ugyldig numerisk node-ID") from exc
        if not 0 <= numeric <= 0xFFFFFFFF:
            raise ValueError("Numerisk node-ID er utenfor 32-bit-området")
        return f"!{numeric:08x}", numeric

    if text.startswith("!"):
        text = text[1:]
    if len(text) != 8 or any(char not in "0123456789abcdef" for char in text):
        raise ValueError("Node-ID må være ! etterfulgt av åtte heksadesimale tegn")
    numeric = int(text, 16)
    if num not in (None, ""):
        try:
            supplied = int(num)
        except (TypeError, ValueError) as exc:
            raise ValueError("Ugyldig numerisk node-ID") from exc
        if supplied != numeric:
            raise ValueError("Node-ID og numerisk nodeverdi samsvarer ikke")
    return f"!{text}", numeric


class SuspiciousPositionError(ValueError):
    """Raised internally for a narrowly identified corrupt position."""


class PositionStore:
    """Store validated latest positions and an append-only position history.

    The class deliberately stores coordinates as Meshtastic integer degrees
    (1e-7 degree units).  Conversion to floating-point display values happens
    only when rows are returned to callers.  Latest-position revisions and
    history sequences are independent so existing ``PREQ/POS/PDONE`` clients
    remain compatible while beta3 history uses its own cursor.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
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

        ``sqlite3.Connection`` commits/rolls back as a context manager but does
        not close itself.  Position status is polled by long-lived bridge
        processes, so deterministic close is required to keep DB/WAL file
        descriptors bounded independently of Python garbage collection.
        """
        con = self._connect()
        try:
            with con:
                yield con
        finally:
            con.close()

    def _init_db(self) -> None:
        with self._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS node_positions_latest (
                    network TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    num INTEGER NOT NULL,
                    latitude_i INTEGER NOT NULL,
                    longitude_i INTEGER NOT NULL,
                    altitude INTEGER,
                    position_epoch INTEGER NOT NULL,
                    position_time_source TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    received_epoch INTEGER NOT NULL,
                    location_source INTEGER,
                    altitude_source INTEGER,
                    precision_bits INTEGER,
                    sats_in_view INTEGER,
                    fix_quality INTEGER,
                    fix_type INTEGER,
                    channel INTEGER,
                    rx_rssi INTEGER,
                    rx_snr REAL,
                    packet_id TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(network, node_id)
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS position_state (
                    network TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL DEFAULT 0,
                    remote_revision INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS position_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS node_positions_history (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    network TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    num INTEGER NOT NULL,
                    latitude_i INTEGER NOT NULL,
                    longitude_i INTEGER NOT NULL,
                    altitude INTEGER,
                    position_epoch INTEGER NOT NULL,
                    position_time_source TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    received_epoch INTEGER NOT NULL,
                    location_source INTEGER,
                    altitude_source INTEGER,
                    precision_bits INTEGER,
                    sats_in_view INTEGER,
                    fix_quality INTEGER,
                    fix_type INTEGER,
                    channel INTEGER,
                    rx_rssi INTEGER,
                    rx_snr REAL,
                    packet_id TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL,
                    observation_key TEXT NOT NULL,
                    sync_origin TEXT NOT NULL DEFAULT '',
                    remote_sequence INTEGER,
                    stored_at TEXT NOT NULL,
                    ingested_epoch INTEGER,
                    UNIQUE(network, node_id, observation_key)
                )
                """
            )
            history_columns = {str(row[1]) for row in con.execute("PRAGMA table_info(node_positions_history)")}
            if "ingested_epoch" not in history_columns:
                con.execute("ALTER TABLE node_positions_history ADD COLUMN ingested_epoch INTEGER")
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_position_history_retention_ingested_epoch "
                "ON node_positions_history(ingested_epoch, sequence)"
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS position_history_state (
                    network TEXT PRIMARY KEY,
                    remote_sequence INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_positions_network_revision "
                "ON node_positions_latest(network, revision)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_positions_position_epoch "
                "ON node_positions_latest(position_epoch)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_position_history_network_sequence "
                "ON node_positions_history(network, sequence)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_position_history_node_epoch "
                "ON node_positions_history(network, node_id, position_epoch)"
            )
            con.execute(
                "INSERT OR IGNORE INTO position_settings(key, value) VALUES "
                "('storage_enabled', '1'), ('stale_minutes', ?)",
                (str(DEFAULT_STALE_MINUTES),),
            )

    @staticmethod
    def _normalize_network(value: Any) -> str:
        network = str(value or "").strip()
        if not network:
            raise ValueError("Nettverk kan ikke være tomt")
        if len(network) > 64 or "\n" in network or "\r" in network:
            raise ValueError("Ugyldig nettverksnavn")
        return network

    @staticmethod
    def _optional_int(value: Any, field: str) -> int | None:
        if value in (None, ""):
            return None
        if isinstance(value, bool):
            raise ValueError(f"{field} må være et heltall")
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{field} må være et heltall") from exc

    @classmethod
    def _optional_enum_int(
        cls,
        value: Any,
        field: str,
        names: Mapping[str, int],
    ) -> int | None:
        """Normalize an optional protobuf enum represented as int or name.

        Meshtastic's ``MessageToDict`` emits enum names such as
        ``LOC_INTERNAL`` and ``ALT_INTERNAL`` while older synthetic packets and
        synchronized rows may contain their numeric protobuf values.
        """
        if value in (None, ""):
            return None
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            enum_name = stripped.rsplit(".", 1)[-1].upper()
            if enum_name in names:
                return int(names[enum_name])
        enum_name = getattr(value, "name", None)
        if isinstance(enum_name, str) and enum_name.upper() in names:
            return int(names[enum_name.upper()])
        enum_value = getattr(value, "value", value)
        return cls._optional_int(enum_value, field)

    @staticmethod
    def _optional_float(value: Any, field: str) -> float | None:
        if value in (None, ""):
            return None
        if isinstance(value, bool):
            raise ValueError(f"{field} må være et tall")
        try:
            result = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{field} må være et tall") from exc
        if not math.isfinite(result):
            raise ValueError(f"{field} må være et endelig tall")
        return result

    @staticmethod
    def _first_present(mapping: Mapping[str, Any], *names: str) -> tuple[bool, Any]:
        for name in names:
            if name in mapping:
                return True, mapping[name]
        return False, None

    @classmethod
    def _coordinate_i(
        cls,
        position: Mapping[str, Any],
        integer_names: tuple[str, ...],
        degree_names: tuple[str, ...],
        minimum: int,
        maximum: int,
        field: str,
    ) -> int:
        present, value = cls._first_present(position, *integer_names)
        if present:
            if isinstance(value, bool):
                raise ValueError(f"{field} må være et heltall")
            try:
                integer = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{field} må være et heltall") from exc
        else:
            present, value = cls._first_present(position, *degree_names)
            if not present:
                raise ValueError(f"{field} mangler")
            if isinstance(value, bool):
                raise ValueError(f"{field} må være et tall")
            try:
                degrees = float(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{field} må være et tall") from exc
            if not math.isfinite(degrees):
                raise ValueError(f"{field} må være et endelig tall")
            integer = int(round(degrees * 10_000_000))
        if not minimum <= integer <= maximum:
            raise ValueError(f"{field} er utenfor gyldig område")
        return integer

    @classmethod
    def _normalize_position(
        cls,
        position: Mapping[str, Any],
        *,
        packet_rx_epoch: Any,
        received_epoch: int,
    ) -> dict[str, Any]:
        if not isinstance(position, Mapping):
            raise ValueError("Posisjon må være et objekt")
        latitude_i = cls._coordinate_i(
            position,
            ("latitude_i", "latitudeI"),
            ("latitude",),
            -900_000_000,
            900_000_000,
            "Breddegrad",
        )
        longitude_i = cls._coordinate_i(
            position,
            ("longitude_i", "longitudeI"),
            ("longitude",),
            -1_800_000_000,
            1_800_000_000,
            "Lengdegrad",
        )

        time_source = "received_at"
        position_epoch: int | None = None
        for key, source_name in (("timestamp", "timestamp"), ("time", "time")):
            if key in position and position[key] not in (None, ""):
                position_epoch = cls._optional_int(position[key], key)
                time_source = source_name
                break
        if position_epoch is None and packet_rx_epoch not in (None, ""):
            position_epoch = cls._optional_int(packet_rx_epoch, "rxTime")
            time_source = "rxTime"
        if position_epoch is None:
            position_epoch = int(received_epoch)
        if position_epoch < 0:
            raise ValueError("Posisjonstid kan ikke være negativ")

        precision_bits = cls._optional_int(
            position.get("precision_bits", position.get("precisionBits")),
            "Presisjonsbiter",
        )
        if is_suspicious_precision_midpoint(
            latitude_i,
            longitude_i,
            precision_bits,
        ):
            raise SuspiciousPositionError(
                "Mistenkelig presisjonsmidtpunkt-signatur"
            )

        return {
            "latitude_i": latitude_i,
            "longitude_i": longitude_i,
            "altitude": cls._optional_int(
                position.get("altitude"), "Høyde"
            ),
            "position_epoch": int(position_epoch),
            "position_time_source": time_source,
            "location_source": cls._optional_enum_int(
                position.get("location_source", position.get("locationSource")),
                "Posisjonskilde",
                LOCATION_SOURCE_VALUES,
            ),
            "altitude_source": cls._optional_enum_int(
                position.get("altitude_source", position.get("altitudeSource")),
                "Høydekilde",
                ALTITUDE_SOURCE_VALUES,
            ),
            "precision_bits": precision_bits,
            "sats_in_view": cls._optional_int(
                position.get("sats_in_view", position.get("satsInView")),
                "Satellitter",
            ),
            "fix_quality": cls._optional_int(
                position.get("fix_quality", position.get("fixQuality")),
                "Fix-kvalitet",
            ),
            "fix_type": cls._optional_int(
                position.get("fix_type", position.get("fixType")),
                "Fix-type",
            ),
        }

    @staticmethod
    def _next_revision(con: sqlite3.Connection, network: str) -> int:
        con.execute(
            "INSERT OR IGNORE INTO position_state(network, revision, remote_revision) "
            "VALUES (?, 0, 0)",
            (network,),
        )
        con.execute(
            "UPDATE position_state SET revision = revision + 1 WHERE network = ?",
            (network,),
        )
        row = con.execute(
            "SELECT revision FROM position_state WHERE network = ?", (network,)
        ).fetchone()
        return int(row[0])

    @staticmethod
    def _meaningful_tuple(row: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            int(row["latitude_i"]),
            int(row["longitude_i"]),
            row["altitude"],
            int(row["position_epoch"]),
            str(row["position_time_source"]),
            row["location_source"],
            row["altitude_source"],
            row["precision_bits"],
            row["sats_in_view"],
            row["fix_quality"],
            row["fix_type"],
            row["channel"],
            row["rx_rssi"],
            row["rx_snr"],
            str(row["packet_id"]),
            str(row["source"]),
        )

    @staticmethod
    def _history_observation_key(row: Mapping[str, Any]) -> str:
        """Return a stable key for one physical position observation.

        Radio-delivery metadata is deliberately excluded.  Repeating the same
        fix with another RSSI, SNR, channel, packet ID or receive timestamp must
        not create artificial movement in the history.
        """
        payload = (
            int(row["position_epoch"]),
            int(row["latitude_i"]),
            int(row["longitude_i"]),
            row.get("altitude"),
            row.get("location_source"),
            row.get("altitude_source"),
            row.get("precision_bits"),
            row.get("sats_in_view"),
            row.get("fix_quality"),
            row.get("fix_type"),
        )
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def _insert_history(
        cls,
        con: sqlite3.Connection,
        *,
        network: str,
        node_id: str,
        num: int,
        row: Mapping[str, Any],
        received_at: str,
        received_epoch: int,
        stored_at: str,
        sync_origin: str = "",
        remote_sequence: int | None = None,
    ) -> str:
        """Insert one deduplicated history point in the current transaction."""
        observation_key = cls._history_observation_key(row)
        ingested_epoch = int(time.time())
        cursor = con.execute(
            """
            INSERT OR IGNORE INTO node_positions_history(
                network, node_id, num, latitude_i, longitude_i, altitude,
                position_epoch, position_time_source, received_at,
                received_epoch, location_source, altitude_source,
                precision_bits, sats_in_view, fix_quality, fix_type,
                channel, rx_rssi, rx_snr, packet_id, source,
                observation_key, sync_origin, remote_sequence, stored_at,
                ingested_epoch
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                network,
                node_id,
                num,
                row["latitude_i"],
                row["longitude_i"],
                row["altitude"],
                row["position_epoch"],
                row["position_time_source"],
                received_at,
                received_epoch,
                row["location_source"],
                row["altitude_source"],
                row["precision_bits"],
                row["sats_in_view"],
                row["fix_quality"],
                row["fix_type"],
                row["channel"],
                row["rx_rssi"],
                row["rx_snr"],
                row["packet_id"],
                row["source"],
                observation_key,
                str(sync_origin or ""),
                remote_sequence,
                stored_at,
                ingested_epoch,
            ),
        )
        return "created" if int(cursor.rowcount) == 1 else "duplicate"

    @staticmethod
    def _equal_epoch_is_improvement(
        existing: sqlite3.Row, candidate: Mapping[str, Any]
    ) -> bool:
        old_precision = existing["precision_bits"]
        new_precision = candidate["precision_bits"]
        precision_better = (
            new_precision is not None
            and (old_precision is None or int(new_precision) > int(old_precision))
        )
        fills_altitude = existing["altitude"] is None and candidate["altitude"] is not None
        coordinates_changed = (
            int(existing["latitude_i"]) != int(candidate["latitude_i"])
            or int(existing["longitude_i"]) != int(candidate["longitude_i"])
        )
        precision_not_worse = (
            old_precision is None
            or new_precision is None
            or int(new_precision) >= int(old_precision)
        )
        metadata_filled = any(
            existing[name] is None and candidate[name] is not None
            for name in (
                "location_source",
                "altitude_source",
                "sats_in_view",
                "fix_quality",
                "fix_type",
                "channel",
                "rx_rssi",
                "rx_snr",
            )
        )
        return bool(
            precision_better
            or fills_altitude
            or metadata_filled
            or (coordinates_changed and precision_not_worse)
        )

    def storage_enabled(self) -> bool:
        with self._connection() as con:
            row = con.execute(
                "SELECT value FROM position_settings WHERE key = 'storage_enabled'"
            ).fetchone()
        return row is None or str(row[0]).strip() not in {"0", "false", "False"}

    def set_storage_enabled(self, enabled: bool) -> None:
        if not isinstance(enabled, bool):
            raise ValueError("Lagringsvalg må være sann eller usann")
        with self._connection() as con:
            con.execute(
                "INSERT INTO position_settings(key, value) VALUES "
                "('storage_enabled', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                ("1" if enabled else "0",),
            )

    def stale_minutes(self) -> int:
        with self._connection() as con:
            row = con.execute(
                "SELECT value FROM position_settings WHERE key = 'stale_minutes'"
            ).fetchone()
        try:
            value = int(row[0]) if row is not None else DEFAULT_STALE_MINUTES
        except (TypeError, ValueError):
            return DEFAULT_STALE_MINUTES
        return max(1, min(MAX_STALE_MINUTES, value))

    def set_stale_minutes(self, minutes: int) -> None:
        if isinstance(minutes, bool) or not isinstance(minutes, int):
            raise ValueError("Aldersgrensen må være et heltall")
        if not 1 <= minutes <= MAX_STALE_MINUTES:
            raise ValueError("Aldersgrensen er utenfor tillatt område")
        with self._connection() as con:
            con.execute(
                "INSERT INTO position_settings(key, value) VALUES "
                "('stale_minutes', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(minutes),),
            )

    def upsert_latest(
        self,
        network: str,
        node_id: Any,
        position: Mapping[str, Any],
        *,
        num: Any = None,
        packet_rx_epoch: Any = None,
        received_epoch: int | None = None,
        received_at: str | None = None,
        source: str,
        packet_id: Any = "",
        channel: Any = None,
        rx_rssi: Any = None,
        rx_snr: Any = None,
        external_revision: int | None = None,
        record_history: bool = True,
    ) -> str:
        """Record a valid observation and update latest position when eligible.

        Direct radio observations are appended to history by default.  Latest
        snapshots received through ``POS`` synchronization pass
        ``record_history=False`` because the separate beta3 history stream is
        authoritative for historical points.
        """
        if not self.storage_enabled():
            return "disabled"
        try:
            normalized_network = self._normalize_network(network)
            normalized_id, normalized_num = canonical_node_id(node_id, num)
            effective_received_epoch = (
                int(time.time()) if received_epoch is None else int(received_epoch)
            )
            if effective_received_epoch < 0:
                raise ValueError("Mottakstid kan ikke være negativ")
            normalized = self._normalize_position(
                position,
                packet_rx_epoch=packet_rx_epoch,
                received_epoch=effective_received_epoch,
            )
            normalized.update(
                {
                    "channel": self._optional_int(channel, "Kanal"),
                    "rx_rssi": self._optional_int(rx_rssi, "RSSI"),
                    "rx_snr": self._optional_float(rx_snr, "SNR"),
                    "packet_id": str(packet_id or "").strip(),
                    "source": str(source or "").strip(),
                }
            )
            if not normalized["source"]:
                raise ValueError("Kilde kan ikke være tom")
            if received_at is None:
                received_at = datetime.fromtimestamp(
                    effective_received_epoch
                ).astimezone().isoformat(timespec="seconds")
            else:
                parsed = datetime.fromisoformat(str(received_at))
                if parsed.tzinfo is None:
                    raise ValueError("Mottakstid må inneholde tidssone")
                received_at = str(received_at)
            ext_revision = None
            if external_revision is not None:
                if isinstance(external_revision, bool):
                    raise ValueError("Ekstern revisjon må være et heltall")
                ext_revision = int(external_revision)
                if ext_revision <= 0:
                    raise ValueError("Ekstern revisjon må være større enn null")
        except SuspiciousPositionError:
            return "suspicious"
        except (TypeError, ValueError, OverflowError):
            return "invalid"

        with self._connection() as con:
            existing = con.execute(
                "SELECT * FROM node_positions_latest "
                "WHERE network = ? AND node_id = ?",
                (normalized_network, normalized_id),
            ).fetchone()
            stamp = now_iso()
            if record_history:
                self._insert_history(
                    con,
                    network=normalized_network,
                    node_id=normalized_id,
                    num=normalized_num,
                    row=normalized,
                    received_at=received_at,
                    received_epoch=effective_received_epoch,
                    stored_at=stamp,
                )
            if existing is not None:
                old_epoch = int(existing["position_epoch"])
                new_epoch = int(normalized["position_epoch"])
                if new_epoch < old_epoch:
                    return "older"
                candidate = {
                    **normalized,
                    "received_epoch": effective_received_epoch,
                }
                if new_epoch == old_epoch:
                    old_tuple = self._meaningful_tuple(existing)
                    new_tuple = self._meaningful_tuple(candidate)
                    if old_tuple == new_tuple:
                        return "duplicate"
                    if not self._equal_epoch_is_improvement(existing, candidate):
                        return "duplicate"

            revision = (
                ext_revision
                if ext_revision is not None
                else self._next_revision(con, normalized_network)
            )
            con.execute(
                """
                INSERT INTO node_positions_latest(
                    network, node_id, num, latitude_i, longitude_i, altitude,
                    position_epoch, position_time_source, received_at,
                    received_epoch, location_source, altitude_source,
                    precision_bits, sats_in_view, fix_quality, fix_type,
                    channel, rx_rssi, rx_snr, packet_id, source, revision,
                    updated_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?
                )
                ON CONFLICT(network, node_id) DO UPDATE SET
                    num = excluded.num,
                    latitude_i = excluded.latitude_i,
                    longitude_i = excluded.longitude_i,
                    altitude = excluded.altitude,
                    position_epoch = excluded.position_epoch,
                    position_time_source = excluded.position_time_source,
                    received_at = excluded.received_at,
                    received_epoch = excluded.received_epoch,
                    location_source = excluded.location_source,
                    altitude_source = excluded.altitude_source,
                    precision_bits = excluded.precision_bits,
                    sats_in_view = excluded.sats_in_view,
                    fix_quality = excluded.fix_quality,
                    fix_type = excluded.fix_type,
                    channel = excluded.channel,
                    rx_rssi = excluded.rx_rssi,
                    rx_snr = excluded.rx_snr,
                    packet_id = excluded.packet_id,
                    source = excluded.source,
                    revision = excluded.revision,
                    updated_at = excluded.updated_at
                """,
                (
                    normalized_network,
                    normalized_id,
                    normalized_num,
                    normalized["latitude_i"],
                    normalized["longitude_i"],
                    normalized["altitude"],
                    normalized["position_epoch"],
                    normalized["position_time_source"],
                    received_at,
                    effective_received_epoch,
                    normalized["location_source"],
                    normalized["altitude_source"],
                    normalized["precision_bits"],
                    normalized["sats_in_view"],
                    normalized["fix_quality"],
                    normalized["fix_type"],
                    normalized["channel"],
                    normalized["rx_rssi"],
                    normalized["rx_snr"],
                    normalized["packet_id"],
                    normalized["source"],
                    revision,
                    stamp,
                ),
            )
            if ext_revision is not None:
                con.execute(
                    "INSERT OR IGNORE INTO position_state(network, revision, remote_revision) "
                    "VALUES (?, 0, 0)",
                    (normalized_network,),
                )
            return "created" if existing is None else "updated"

    def store_history_snapshot(
        self,
        network: str,
        node_id: Any,
        payload: Mapping[str, Any],
        *,
        num: Any = None,
        external_sequence: int,
        sync_origin: str,
    ) -> str:
        """Store one validated history point received from another station."""
        if not self.storage_enabled():
            return "disabled"
        try:
            if isinstance(external_sequence, bool):
                raise ValueError("Ekstern historikksekvens må være et heltall")
            remote_sequence = int(external_sequence)
            if remote_sequence <= 0:
                raise ValueError("Ekstern historikksekvens må være større enn null")
            normalized_network = self._normalize_network(network)
            normalized_id, normalized_num = canonical_node_id(node_id, num)
            received_epoch = int(payload.get("received_epoch", time.time()))
            if received_epoch < 0:
                raise ValueError("Mottakstid kan ikke være negativ")
            time_source = str(payload.get("position_time_source") or "")
            position: dict[str, Any] = {
                key: payload.get(key)
                for key in (
                    "latitude_i",
                    "longitude_i",
                    "altitude",
                    "location_source",
                    "altitude_source",
                    "precision_bits",
                    "sats_in_view",
                    "fix_quality",
                    "fix_type",
                )
                if key in payload
            }
            position_epoch = payload.get("position_epoch")
            if position_epoch not in (None, ""):
                if time_source == "time":
                    position["time"] = position_epoch
                elif time_source == "timestamp":
                    position["timestamp"] = position_epoch
                elif time_source == "rxTime":
                    pass
                else:
                    # Validate the explicit epoch through the existing parser;
                    # restore the original source label immediately afterwards.
                    position["timestamp"] = position_epoch
            packet_rx_epoch = position_epoch if time_source == "rxTime" else None
            normalized = self._normalize_position(
                position,
                packet_rx_epoch=packet_rx_epoch,
                received_epoch=received_epoch,
            )
            if position_epoch not in (None, ""):
                normalized["position_epoch"] = int(position_epoch)
                normalized["position_time_source"] = time_source or "received_at"
            normalized.update(
                {
                    "channel": self._optional_int(payload.get("channel"), "Kanal"),
                    "rx_rssi": self._optional_int(payload.get("rx_rssi"), "RSSI"),
                    "rx_snr": self._optional_float(payload.get("rx_snr"), "SNR"),
                    "packet_id": str(payload.get("packet_id") or "").strip(),
                    "source": str(payload.get("source") or "").strip(),
                }
            )
            if not normalized["source"]:
                raise ValueError("Kilde kan ikke være tom")
            received_at = str(payload.get("received_at") or "")
            parsed = datetime.fromisoformat(received_at)
            if parsed.tzinfo is None:
                raise ValueError("Mottakstid må inneholde tidssone")
            stored_at = str(payload.get("stored_at") or now_iso())
            stored = datetime.fromisoformat(stored_at)
            if stored.tzinfo is None:
                raise ValueError("Lagringstid må inneholde tidssone")
        except SuspiciousPositionError:
            return "suspicious"
        except (TypeError, ValueError, OverflowError):
            return "invalid"

        with self._connection() as con:
            return self._insert_history(
                con,
                network=normalized_network,
                node_id=normalized_id,
                num=normalized_num,
                row=normalized,
                received_at=received_at,
                received_epoch=received_epoch,
                stored_at=stored_at,
                sync_origin=sync_origin,
                remote_sequence=remote_sequence,
            )

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["latitude"] = int(row["latitude_i"]) / 10_000_000.0
        value["longitude"] = int(row["longitude_i"]) / 10_000_000.0
        return value

    @staticmethod
    def _row_is_suspicious(row: Mapping[str, Any]) -> bool:
        return is_suspicious_precision_midpoint(
            row["latitude_i"],
            row["longitude_i"],
            row["precision_bits"],
        )

    def get_latest(self, network: str, node_id: Any) -> dict[str, Any] | None:
        normalized_network = self._normalize_network(network)
        normalized_id, _ = canonical_node_id(node_id)
        with self._connection() as con:
            row = con.execute(
                "SELECT * FROM node_positions_latest "
                "WHERE network = ? AND node_id = ?",
                (normalized_network, normalized_id),
            ).fetchone()
        if row is None or self._row_is_suspicious(row):
            return None
        return self._row_to_dict(row)

    def list_latest(
        self, network: str | None = None, *, since_revision: int = 0
    ) -> list[dict[str, Any]]:
        if isinstance(since_revision, bool):
            raise ValueError("Revisjon må være et heltall")
        cursor = max(0, int(since_revision))
        with self._connection() as con:
            if network is None:
                rows = con.execute(
                    "SELECT * FROM node_positions_latest "
                    "WHERE revision > ? ORDER BY network, revision, node_id",
                    (cursor,),
                ).fetchall()
            else:
                normalized_network = self._normalize_network(network)
                rows = con.execute(
                    "SELECT * FROM node_positions_latest "
                    "WHERE network = ? AND revision > ? "
                    "ORDER BY revision, node_id",
                    (normalized_network, cursor),
                ).fetchall()
        return [
            self._row_to_dict(row)
            for row in rows
            if not self._row_is_suspicious(row)
        ]

    def list_history(
        self,
        network: str | None = None,
        node_id: Any = None,
        *,
        limit: int = 250,
        newest_first: bool = True,
    ) -> list[dict[str, Any]]:
        """Return a bounded local history list for GUI display."""
        safe_limit = max(1, min(int(limit), 5000))
        clauses: list[str] = []
        parameters: list[Any] = []
        if network is not None:
            clauses.append("network = ?")
            parameters.append(self._normalize_network(network))
        if node_id not in (None, ""):
            normalized_id, _ = canonical_node_id(node_id)
            clauses.append("node_id = ?")
            parameters.append(normalized_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        order = "DESC" if newest_first else "ASC"
        with self._connection() as con:
            rows = con.execute(
                f"SELECT * FROM node_positions_history{where} "
                f"ORDER BY sequence {order} LIMIT ?",
                (*parameters, safe_limit),
            ).fetchall()
        return [
            self._row_to_dict(row)
            for row in rows
            if not self._row_is_suspicious(row)
        ]

    @staticmethod
    def _normalize_export_limit(value: Any) -> int:
        if isinstance(value, bool):
            raise ValueError("Eksportgrense må være et heltall")
        try:
            limit = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("Eksportgrense må være et heltall") from exc
        if not 1 <= limit <= MAX_EXPORT_HISTORY_ROWS:
            raise ValueError(
                f"Eksportgrense må være mellom 1 og {MAX_EXPORT_HISTORY_ROWS}"
            )
        return limit

    @staticmethod
    def _normalize_optional_epoch(value: Any, field: str) -> int | None:
        if value in (None, ""):
            return None
        if isinstance(value, bool):
            raise ValueError(f"{field} må være et heltall")
        try:
            epoch = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{field} må være et heltall") from exc
        if epoch < 0:
            raise ValueError(f"{field} kan ikke være negativ")
        return epoch

    def history_nodes(self, network: str | None = None) -> list[dict[str, Any]]:
        """Return distinct history node identities for export selection."""
        parameters: tuple[Any, ...] = ()
        where = ""
        if network is not None:
            where = " WHERE network = ?"
            parameters = (self._normalize_network(network),)
        with self._connection() as con:
            rows = con.execute(
                "SELECT network, node_id, num, COUNT(*) AS history_count, "
                "MIN(position_epoch) AS first_epoch, "
                "MAX(position_epoch) AS last_epoch "
                f"FROM node_positions_history{where} "
                "GROUP BY network, node_id, num "
                "ORDER BY network, node_id",
                parameters,
            ).fetchall()
        return [dict(row) for row in rows]

    def history_by_sequences(
        self,
        sequences: Any,
        *,
        max_rows: int = MAX_EXPORT_HISTORY_ROWS,
    ) -> list[dict[str, Any]]:
        """Return selected history rows in chronological order for export."""
        safe_limit = self._normalize_export_limit(max_rows)
        if isinstance(sequences, (str, bytes)):
            raise ValueError("Historikksekvenser må være en liste med heltall")
        try:
            raw_sequences = list(sequences)
        except TypeError as exc:
            raise ValueError(
                "Historikksekvenser må være en liste med heltall"
            ) from exc
        normalized: list[int] = []
        for value in raw_sequences:
            if isinstance(value, bool):
                raise ValueError("Historikksekvens må være et heltall")
            try:
                sequence = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError("Historikksekvens må være et heltall") from exc
            if sequence <= 0:
                raise ValueError("Historikksekvens må være større enn null")
            if sequence not in normalized:
                normalized.append(sequence)
        if not normalized:
            return []
        if len(normalized) > safe_limit:
            raise ValueError(
                f"Eksporten kan inneholde maksimalt {safe_limit} posisjoner"
            )

        rows: list[sqlite3.Row] = []
        with self._connection() as con:
            for start in range(0, len(normalized), 500):
                chunk = normalized[start : start + 500]
                placeholders = ",".join("?" for _ in chunk)
                rows.extend(
                    con.execute(
                        "SELECT * FROM node_positions_history "
                        f"WHERE sequence IN ({placeholders})",
                        tuple(chunk),
                    ).fetchall()
                )
        found = {int(row["sequence"]) for row in rows}
        missing = sorted(set(normalized).difference(found))
        if missing:
            raise ValueError(
                "Valgte historikkrader finnes ikke lenger: "
                + ", ".join(str(value) for value in missing[:10])
            )
        rows.sort(key=lambda row: (int(row["position_epoch"]), int(row["sequence"])))
        return [
            self._row_to_dict(row)
            for row in rows
            if not self._row_is_suspicious(row)
        ]

    def history_for_export(
        self,
        network: str,
        node_id: Any,
        *,
        from_epoch: Any = None,
        to_epoch: Any = None,
        max_rows: int = MAX_EXPORT_HISTORY_ROWS,
    ) -> list[dict[str, Any]]:
        """Return one node's history in an inclusive position-time range."""
        normalized_network = self._normalize_network(network)
        normalized_id, _ = canonical_node_id(node_id)
        start_epoch = self._normalize_optional_epoch(from_epoch, "Fra-tid")
        end_epoch = self._normalize_optional_epoch(to_epoch, "Til-tid")
        if (
            start_epoch is not None
            and end_epoch is not None
            and start_epoch > end_epoch
        ):
            raise ValueError("Fra-tid kan ikke være etter til-tid")
        safe_limit = self._normalize_export_limit(max_rows)
        clauses = ["network = ?", "node_id = ?"]
        parameters: list[Any] = [normalized_network, normalized_id]
        if start_epoch is not None:
            clauses.append("position_epoch >= ?")
            parameters.append(start_epoch)
        if end_epoch is not None:
            clauses.append("position_epoch <= ?")
            parameters.append(end_epoch)
        with self._connection() as con:
            rows = con.execute(
                "SELECT * FROM node_positions_history WHERE "
                + " AND ".join(clauses)
                + " ORDER BY position_epoch ASC, sequence ASC LIMIT ?",
                (*parameters, safe_limit + 1),
            ).fetchall()
        if len(rows) > safe_limit:
            raise ValueError(
                f"Eksporten kan inneholde maksimalt {safe_limit} posisjoner"
            )
        return [
            self._row_to_dict(row)
            for row in rows
            if not self._row_is_suspicious(row)
        ]

    def history_since(
        self,
        network: str,
        sequence: int,
        limit: int,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Return one bounded ascending history batch after ``sequence``."""
        normalized_network = self._normalize_network(network)
        safe_limit = max(1, min(int(limit), 50))
        cursor = max(0, int(sequence))
        with self._connection() as con:
            rows = con.execute(
                "SELECT * FROM node_positions_history "
                "WHERE network = ? AND sequence > ? "
                "ORDER BY sequence ASC LIMIT ?",
                (normalized_network, cursor, safe_limit + 1),
            ).fetchall()
        more = len(rows) > safe_limit
        rows = rows[:safe_limit]
        return (
            [
                self._row_to_dict(row)
                for row in rows
                if not self._row_is_suspicious(row)
            ],
            more,
        )

    def history_count(self, network: str | None = None) -> int:
        with self._connection() as con:
            if network is None:
                row = con.execute(
                    "SELECT COUNT(*) FROM node_positions_history"
                ).fetchone()
            else:
                row = con.execute(
                    "SELECT COUNT(*) FROM node_positions_history WHERE network = ?",
                    (self._normalize_network(network),),
                ).fetchone()
        return int(row[0]) if row is not None else 0

    def current_history_sequence(self, network: str) -> int:
        normalized_network = self._normalize_network(network)
        with self._connection() as con:
            row = con.execute(
                "SELECT COALESCE(MAX(sequence), 0) FROM node_positions_history "
                "WHERE network = ?",
                (normalized_network,),
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def history_sync_cursor(self, network: str) -> int:
        normalized_network = self._normalize_network(network)
        with self._connection() as con:
            row = con.execute(
                "SELECT remote_sequence FROM position_history_state "
                "WHERE network = ?",
                (normalized_network,),
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def set_history_sync_cursor(self, network: str, sequence: int) -> None:
        normalized_network = self._normalize_network(network)
        if isinstance(sequence, bool):
            raise ValueError("Historikksekvens må være et heltall")
        normalized_sequence = max(0, int(sequence))
        with self._connection() as con:
            con.execute(
                """
                INSERT INTO position_history_state(
                    network, remote_sequence, updated_at
                ) VALUES (?, ?, ?)
                ON CONFLICT(network) DO UPDATE SET
                    remote_sequence = MAX(
                        position_history_state.remote_sequence,
                        excluded.remote_sequence
                    ),
                    updated_at = excluded.updated_at
                """,
                (normalized_network, normalized_sequence, now_iso()),
            )

    def count(self, network: str | None = None) -> int:
        with self._connection() as con:
            if network is None:
                rows = con.execute(
                    "SELECT latitude_i, longitude_i, precision_bits "
                    "FROM node_positions_latest"
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT latitude_i, longitude_i, precision_bits "
                    "FROM node_positions_latest WHERE network = ?",
                    (self._normalize_network(network),),
                ).fetchall()
        return sum(not self._row_is_suspicious(row) for row in rows)

    def raw_count(self, network: str | None = None) -> int:
        """Return all stored rows, including legacy suspicious rows."""
        with self._connection() as con:
            if network is None:
                row = con.execute(
                    "SELECT COUNT(*) FROM node_positions_latest"
                ).fetchone()
            else:
                row = con.execute(
                    "SELECT COUNT(*) FROM node_positions_latest WHERE network = ?",
                    (self._normalize_network(network),),
                ).fetchone()
        return int(row[0]) if row is not None else 0

    def suspicious_count(self, network: str | None = None) -> int:
        """Return rows matching only the exact known corrupt signature."""
        normalized_network = (
            self._normalize_network(network) if network is not None else None
        )
        with self._connection() as con:
            if normalized_network is None:
                rows = con.execute(
                    "SELECT latitude_i, longitude_i, precision_bits "
                    "FROM node_positions_latest"
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT latitude_i, longitude_i, precision_bits "
                    "FROM node_positions_latest WHERE network = ?",
                    (normalized_network,),
                ).fetchall()
        return sum(self._row_is_suspicious(row) for row in rows)

    def current_revision(self, network: str) -> int:
        normalized_network = self._normalize_network(network)
        with self._connection() as con:
            row = con.execute(
                "SELECT revision FROM position_state WHERE network = ?",
                (normalized_network,),
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def remote_revision(self, network: str) -> int:
        normalized_network = self._normalize_network(network)
        with self._connection() as con:
            row = con.execute(
                "SELECT remote_revision FROM position_state WHERE network = ?",
                (normalized_network,),
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def set_remote_revision(self, network: str, revision: int) -> None:
        normalized_network = self._normalize_network(network)
        if isinstance(revision, bool):
            raise ValueError("Revisjon må være et heltall")
        normalized_revision = max(0, int(revision))
        with self._connection() as con:
            con.execute(
                """
                INSERT INTO position_state(network, revision, remote_revision)
                VALUES (?, 0, ?)
                ON CONFLICT(network) DO UPDATE SET
                    remote_revision = MAX(position_state.remote_revision,
                                          excluded.remote_revision)
                """,
                (normalized_network, normalized_revision),
            )

    def purge_suspicious_positions(self, network: str | None = None) -> int:
        """Delete legacy rows matching the exact corrupt midpoint signature."""
        normalized_network = (
            self._normalize_network(network) if network is not None else None
        )
        with self._connection() as con:
            if normalized_network is None:
                rows = con.execute(
                    "SELECT network, node_id, latitude_i, longitude_i, "
                    "precision_bits FROM node_positions_latest"
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT network, node_id, latitude_i, longitude_i, "
                    "precision_bits FROM node_positions_latest WHERE network = ?",
                    (normalized_network,),
                ).fetchall()
            keys = [
                (str(row["network"]), str(row["node_id"]))
                for row in rows
                if self._row_is_suspicious(row)
            ]
            con.executemany(
                "DELETE FROM node_positions_latest "
                "WHERE network = ? AND node_id = ?",
                keys,
            )
        return len(keys)

    def clear_positions(self, network: str | None = None) -> int:
        with self._connection() as con:
            if network is None:
                latest_row = con.execute(
                    "SELECT COUNT(*) FROM node_positions_latest"
                ).fetchone()
                history_row = con.execute(
                    "SELECT COUNT(*) FROM node_positions_history"
                ).fetchone()
                con.execute("DELETE FROM node_positions_latest")
                con.execute("DELETE FROM node_positions_history")
            else:
                normalized_network = self._normalize_network(network)
                latest_row = con.execute(
                    "SELECT COUNT(*) FROM node_positions_latest WHERE network = ?",
                    (normalized_network,),
                ).fetchone()
                history_row = con.execute(
                    "SELECT COUNT(*) FROM node_positions_history WHERE network = ?",
                    (normalized_network,),
                ).fetchone()
                con.execute(
                    "DELETE FROM node_positions_latest WHERE network = ?",
                    (normalized_network,),
                )
                con.execute(
                    "DELETE FROM node_positions_history WHERE network = ?",
                    (normalized_network,),
                )
        # Preserve the pre-beta3 return contract: callers historically receive
        # the number of latest-position rows removed. History rows are deleted
        # in the same transaction but reported separately through history_count.
        return int(latest_row[0])

    def aggregate_status(self, network: str | None = None) -> dict[str, Any]:
        """Return privacy-safe counts and ages without exact coordinates.

        When ``network`` is supplied, the aggregate is restricted to that
        route.  This is used by the local meshbridge API so B868 and B433 never
        expose each other's position counts or revisions by accident.
        """
        now_epoch = int(time.time())
        normalized_network = (
            self._normalize_network(network) if network is not None else None
        )
        with self._connection() as con:
            if normalized_network is None:
                rows = con.execute(
                    "SELECT latitude_i, longitude_i, precision_bits, "
                    "position_epoch FROM node_positions_latest"
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT latitude_i, longitude_i, precision_bits, "
                    "position_epoch FROM node_positions_latest WHERE network = ?",
                    (normalized_network,),
                ).fetchall()
        trusted_rows = [row for row in rows if not self._row_is_suspicious(row)]
        epochs = [int(row["position_epoch"]) for row in trusted_rows]
        oldest = min(epochs) if epochs else None
        newest = max(epochs) if epochs else None
        result = {
            "storage_enabled": self.storage_enabled(),
            "stale_minutes": self.stale_minutes(),
            "position_count": len(trusted_rows),
            "history_count": self.history_count(normalized_network),
            "oldest_age_seconds": (
                max(0, now_epoch - int(oldest)) if oldest is not None else None
            ),
            "newest_age_seconds": (
                max(0, now_epoch - int(newest)) if newest is not None else None
            ),
        }
        if normalized_network is not None:
            result.update(
                {
                    "network": normalized_network,
                    "revision": self.current_revision(normalized_network),
                    "remote_revision": self.remote_revision(normalized_network),
                    "history_sequence": self.current_history_sequence(
                        normalized_network
                    ),
                    "history_remote_sequence": self.history_sync_cursor(
                        normalized_network
                    ),
                }
            )
        return result

    def integrity_check(self) -> str:
        with self._connection() as con:
            row = con.execute("PRAGMA quick_check").fetchone()
        return str(row[0]) if row is not None else "unknown"
