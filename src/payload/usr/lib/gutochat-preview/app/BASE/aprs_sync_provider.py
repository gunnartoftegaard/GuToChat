#!/usr/bin/env python3
"""Read-only APRS presentation export for Base→Field synchronization.

FIELD-BASE-PARITY-A1-P1 deliberately exports only the normalized map/presentation
fields needed by GuToMap.  It never creates or migrates the authoritative Base
APRS database and never exposes raw packet text.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

MAX_BATCH = 50
SYNC_SOURCE_TYPE = "local_rf"
SYNC_TRANSPORT = "vhf_ax25"
APRS_PRESENTATION_FIELDS = (
    "station_id", "latitude", "longitude", "altitude_m", "course_deg",
    "speed_kmh", "symbol_table", "symbol_code", "packet_time_raw",
    "received_at", "received_epoch", "source_type", "transport",
    "source_gateway", "packet_path", "comment", "observation_key",
    "position_format", "wind_direction_deg", "wind_speed_kmh", "gust_kmh",
    "temperature_c", "rain_last_hour_mm", "rain_last_24h_mm",
    "rain_since_midnight_mm", "humidity_percent", "pressure_hpa",
)


class AprsSyncProvider:
    """Bounded read-only view over ``aprs_positions_history``."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(f"file:{self.database_path}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        return con

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        con = self._connect()
        try:
            yield con
        finally:
            con.close()

    @staticmethod
    def _table_exists(con: sqlite3.Connection, table: str) -> bool:
        return con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone() is not None

    def current_sequence(self) -> int:
        if not self.database_path.is_file():
            return 0
        with self._connection() as con:
            if not self._table_exists(con, "aprs_positions_history"):
                return 0
            row = con.execute(
                "SELECT COALESCE(MAX(sequence), 0) FROM aprs_positions_history"
            ).fetchone()
            return int(row[0] if row else 0)

    def history_since(
        self, since_sequence: int, limit: int = 10
    ) -> tuple[list[dict[str, Any]], bool, int]:
        since = max(0, int(since_sequence))
        safe_limit = max(1, min(int(limit), MAX_BATCH))
        current = self.current_sequence()
        if since > current:
            raise ValueError("APRS_CURSOR_AHEAD_OF_BASE")
        if not self.database_path.is_file() or current == 0:
            return [], False, current
        columns = ", ".join(("sequence",) + APRS_PRESENTATION_FIELDS)
        with self._connection() as con:
            rows = con.execute(
                f"SELECT {columns} FROM aprs_positions_history "
                "WHERE sequence > ? AND source_type = ? AND transport = ? "
                "ORDER BY sequence ASC LIMIT ?",
                (since, SYNC_SOURCE_TYPE, SYNC_TRANSPORT, safe_limit + 1),
            ).fetchall()
        more = len(rows) > safe_limit
        rows = rows[:safe_limit]
        result = [dict(row) for row in rows]
        # ``final_cursor`` is scan progress, not necessarily the last exported
        # observation. On the final page it advances across excluded APRS-IS
        # rows to the authoritative Base sequence.
        final_cursor = int(result[-1]["sequence"]) if more and result else current
        return result, more, final_cursor

    def snapshot_page(
        self, baseline_sequence: int = 0, after_sequence: int = 0, limit: int = 10
    ) -> tuple[list[dict[str, Any]], bool, int, int]:
        """Return a stable latest-per-station page as-of one locked history sequence.

        The snapshot is derived from history rather than the mutable latest table,
        so packets received after ``baseline`` cannot alter later pages. Paging is
        by the selected observations' unique history sequence.
        """
        current = self.current_sequence()
        baseline = current if int(baseline_sequence) <= 0 else int(baseline_sequence)
        after = max(0, int(after_sequence))
        safe_limit = max(1, min(int(limit), MAX_BATCH))
        if baseline > current:
            raise ValueError("APRS_SNAPSHOT_BASELINE_AHEAD_OF_BASE")
        if after > baseline:
            raise ValueError("APRS_SNAPSHOT_AFTER_AHEAD_OF_BASELINE")
        if not self.database_path.is_file() or baseline == 0:
            return [], False, baseline, after
        columns = ", ".join(f"h.{name}" for name in (("sequence",) + APRS_PRESENTATION_FIELDS))
        with self._connection() as con:
            rows = con.execute(
                "WITH selected AS ("
                "SELECT station_id, MAX(sequence) AS sequence "
                "FROM aprs_positions_history "
                "WHERE sequence <= ? AND source_type = ? AND transport = ? "
                "GROUP BY station_id"
                ") "
                f"SELECT {columns} FROM aprs_positions_history h "
                "JOIN selected s ON s.sequence=h.sequence "
                "WHERE h.sequence > ? ORDER BY h.sequence ASC LIMIT ?",
                (baseline, SYNC_SOURCE_TYPE, SYNC_TRANSPORT, after, safe_limit + 1),
            ).fetchall()
        more = len(rows) > safe_limit
        rows = rows[:safe_limit]
        result = [dict(row) for row in rows]
        # On the final page advance the scan cursor to the fixed snapshot
        # baseline even when no eligible observation exists at that sequence.
        page_after = int(result[-1]["sequence"]) if more and result else baseline
        return result, more, baseline, page_after
