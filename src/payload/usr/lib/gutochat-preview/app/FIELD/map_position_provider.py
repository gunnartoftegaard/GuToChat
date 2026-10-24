#!/usr/bin/env python3
"""Read-only map position providers for Meshtastic and APRS.

APRS-A1.7 keeps transport-specific storage separate while presenting one small,
privacy-reduced row contract to GuToMap.  APRS may live in the product database
or in a separate read-only database selected by configuration.  No network or
radio access is performed here.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Mapping

from offline_map import (
    privacy_reduce_degrees,
    read_latest_positions_read_only,
    read_position_history_read_only,
)

APRS_NETWORK_KEY = "aprs"
MAP_LAYERS = {"meshtastic", "aprs"}
MAX_MAP_PROVIDER_HISTORY = 1000


def resolve_aprs_database_path(
    config: Mapping[str, Any],
    default_database_path: Path,
) -> Path:
    """Resolve the optional APRS map database without creating anything.

    ``map_aprs_database`` is deliberately presentation-only.  If it is absent,
    APRS remains co-located with the normal product database for backward
    compatibility with A1.1-A1.6.  Tilde expansion is supported, but relative
    paths are not silently rebased to the current working directory.
    """
    raw = str(config.get("map_aprs_database") or "").strip()
    if not raw:
        return Path(default_database_path)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ValueError("map_aprs_database must be an absolute path")
    return path


def _readonly_connect(database_path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{Path(database_path)}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (str(table),),
    ).fetchone()
    return row is not None


def _parse_packet_path(value: Any) -> list[str]:
    try:
        parsed = json.loads(str(value or "[]"))
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed if str(item).strip()]


def _meshtastic_row(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item.setdefault("map_layer", "meshtastic")
    item.setdefault("entity_type", "node")
    item.setdefault("entity_id", str(item.get("node_id", "")))
    return item


def _has_weather(value: Mapping[str, Any]) -> bool:
    return any(
        value.get(name) is not None
        for name in (
            "wind_direction_deg",
            "wind_speed_kmh",
            "gust_kmh",
            "temperature_c",
            "rain_last_hour_mm",
            "rain_last_24h_mm",
            "rain_since_midnight_mm",
            "humidity_percent",
            "pressure_hpa",
        )
    )


def _aprs_marker_kind(value: Mapping[str, Any]) -> str:
    if _has_weather(value) or str(value.get("symbol_code") or "") == "_":
        return "weather"
    comment = str(value.get("comment") or "").casefold()
    if "lora" in comment:
        # Presentation hint only.  It must never rewrite the transport field,
        # which remains unknown unless the ingest source can prove it.
        return "lora_hint"
    if str(value.get("position_format") or "") == "mic_e":
        return "mic_e"
    return "station"


def _aprs_row(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    station_id = str(value.get("station_id") or "").upper()
    transport = str(value.get("transport") or "unknown")
    source_type = str(value.get("source_type") or "")
    source_gateway = str(value.get("source_gateway") or "")
    source_parts = [part for part in ("APRS", transport, source_gateway) if part]
    comment = str(value.get("comment") or "")
    symbol_table = str(value.get("symbol_table") or "")
    symbol_code = str(value.get("symbol_code") or "")
    return {
        **value,
        "network": APRS_NETWORK_KEY,
        "node_id": station_id,
        "node_label": station_id,
        "entity_id": station_id,
        "entity_type": "aprs_station",
        "map_layer": "aprs",
        "latitude": privacy_reduce_degrees(value["latitude"]),
        "longitude": privacy_reduce_degrees(value["longitude"]),
        "altitude": value.get("altitude_m"),
        "position_epoch": int(value.get("received_epoch") or 0),
        "position_time_source": "aprs_received",
        "precision_bits": None,
        "source": " / ".join(source_parts) if source_parts else source_type or "APRS",
        "source_type": source_type,
        "transport": transport,
        "source_gateway": source_gateway,
        "packet_path": _parse_packet_path(value.get("packet_path")),
        "aprs_symbol": f"{symbol_table}{symbol_code}" if symbol_table and symbol_code else "",
        "aprs_marker_kind": _aprs_marker_kind(value),
        "aprs_has_weather": _has_weather(value),
        "aprs_lora_hint": "lora" in comment.casefold(),
        "aprs_position_format": str(value.get("position_format") or ""),
    }


def read_aprs_latest_positions_read_only(database_path: Path) -> list[dict[str, Any]]:
    """Return privacy-reduced APRS latest positions without creating tables."""
    path = Path(database_path)
    if not path.is_file():
        return []
    with _readonly_connect(path) as con:
        if not _table_exists(con, "aprs_positions_latest"):
            return []
        rows = con.execute(
            "SELECT * FROM aprs_positions_latest "
            "ORDER BY received_epoch DESC, station_id ASC"
        ).fetchall()
    return [_aprs_row(row) for row in rows]


def read_aprs_position_history_read_only(
    database_path: Path,
    *,
    station_id: str | None = None,
    limit: int = 250,
) -> list[dict[str, Any]]:
    """Return bounded privacy-reduced APRS position history read-only."""
    safe_limit = max(1, min(int(limit), MAX_MAP_PROVIDER_HISTORY))
    path = Path(database_path)
    if not path.is_file():
        return []
    params: list[Any] = []
    where = ""
    if station_id:
        where = " WHERE station_id = ?"
        params.append(str(station_id).strip().upper())
    with _readonly_connect(path) as con:
        if not _table_exists(con, "aprs_positions_history"):
            return []
        rows = con.execute(
            "SELECT * FROM aprs_positions_history"
            f"{where} ORDER BY sequence DESC LIMIT ?",
            (*params, safe_limit),
        ).fetchall()
    return [_aprs_row(row) for row in rows]


def read_map_latest_positions_read_only(
    database_path: Path,
    *,
    meshtastic_network: str | None = None,
    include_aprs: bool = True,
    aprs_database_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Return one normalized latest-position list for the local GuToMap view."""
    product_path = Path(database_path)
    has_meshtastic = False
    if product_path.is_file():
        with _readonly_connect(product_path) as con:
            has_meshtastic = _table_exists(con, "node_positions_latest")
    rows = (
        [
            _meshtastic_row(row)
            for row in read_latest_positions_read_only(
                product_path,
                network=meshtastic_network,
            )
        ]
        if has_meshtastic
        else []
    )
    if include_aprs:
        aprs_path = Path(aprs_database_path) if aprs_database_path is not None else product_path
        rows.extend(read_aprs_latest_positions_read_only(aprs_path))
    return sorted(
        rows,
        key=lambda row: (
            str(row.get("map_layer", "")),
            str(row.get("network", "")),
            str(row.get("node_id", "")),
        ),
    )


def read_map_position_history_read_only(
    database_path: Path,
    *,
    meshtastic_network: str | None = None,
    include_aprs: bool = True,
    limit: int = 250,
    aprs_database_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Return newest-first normalized local history across enabled map layers."""
    safe_limit = max(1, min(int(limit), MAX_MAP_PROVIDER_HISTORY))
    product_path = Path(database_path)
    has_meshtastic = False
    if product_path.is_file():
        with _readonly_connect(product_path) as con:
            has_meshtastic = _table_exists(con, "node_positions_history")
    rows = (
        [
            _meshtastic_row(row)
            for row in read_position_history_read_only(
                product_path,
                network=meshtastic_network,
                limit=safe_limit,
            )
        ]
        if has_meshtastic
        else []
    )
    if include_aprs:
        aprs_path = Path(aprs_database_path) if aprs_database_path is not None else product_path
        rows.extend(
            read_aprs_position_history_read_only(
                aprs_path,
                limit=safe_limit,
            )
        )
    rows.sort(
        key=lambda row: (
            int(row.get("position_epoch") or row.get("received_epoch") or 0),
            int(row.get("sequence") or 0),
            str(row.get("node_id", "")),
        ),
        reverse=True,
    )
    return rows[:safe_limit]


def _database_signature(
    database_path: Path,
    specs: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, int, int, str], ...]:
    path = Path(database_path)
    if not path.is_file():
        return tuple((table, 0, 0, "") for table, _query in specs)
    result: list[tuple[str, int, int, str]] = []
    with _readonly_connect(path) as con:
        for table, query in specs:
            if not _table_exists(con, table):
                result.append((table, 0, 0, ""))
                continue
            row = con.execute(query).fetchone()
            result.append((table, int(row[0]), int(row[1]), str(row[2])))
    return tuple(result)


def map_position_data_signature(
    database_path: Path,
    *,
    aprs_database_path: Path | None = None,
) -> tuple[tuple[str, int, int, str], ...]:
    """Return read-only table signatures for GuToMap refresh throttling.

    Missing optional APRS tables/database contribute zero-valued signatures
    rather than making the existing Meshtastic map unavailable.
    """
    meshtastic_specs = (
        (
            "node_positions_latest",
            "SELECT COUNT(*), COALESCE(MAX(revision), 0), "
            "COALESCE(MAX(updated_at), '') FROM node_positions_latest",
        ),
        (
            "node_positions_history",
            "SELECT COUNT(*), COALESCE(MAX(sequence), 0), "
            "COALESCE(MAX(stored_at), '') FROM node_positions_history",
        ),
    )
    aprs_specs = (
        (
            "aprs_positions_latest",
            "SELECT COUNT(*), COALESCE(MAX(received_epoch), 0), "
            "COALESCE(MAX(updated_at), '') FROM aprs_positions_latest",
        ),
        (
            "aprs_positions_history",
            "SELECT COUNT(*), COALESCE(MAX(sequence), 0), "
            "COALESCE(MAX(stored_at), '') FROM aprs_positions_history",
        ),
    )
    product_path = Path(database_path)
    aprs_path = Path(aprs_database_path) if aprs_database_path is not None else product_path
    return _database_signature(product_path, meshtastic_specs) + _database_signature(aprs_path, aprs_specs)
