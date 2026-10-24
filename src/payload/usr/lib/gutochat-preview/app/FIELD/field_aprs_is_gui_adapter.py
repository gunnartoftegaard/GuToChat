#!/usr/bin/env python3
"""R2-E.A2-A2 GUI adapter for a separate Field APRS-IS presentation cache.

This module performs no network I/O and never creates or mutates a database.
It only reads an already-existing dedicated APRS-IS cache in SQLite read-only
mode and merges it into the presentation view.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from map_position_provider import read_aprs_latest_positions_read_only
from field_aprs_is_presentation import presentation_merge


def read_direct_aprs_is_rows_read_only(cache_db: Path) -> list[dict[str, Any]]:
    """Read the optional direct APRS-IS cache without creating it."""
    path = Path(cache_db)
    if not path.is_file():
        return []
    rows = read_aprs_latest_positions_read_only(path)
    out: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["presentation_source"] = "field_aprs_is"
        item["source"] = "APRS-IS / direct / receive-only"
        item["direct_aprs_is"] = True
        out.append(item)
    return out


def merge_map_rows_for_presentation(
    existing_rows: Iterable[Mapping[str, Any]],
    direct_rows: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Merge direct APRS-IS only at presentation time.

    Meshtastic rows are preserved. Existing Base->Field APRS replica rows and
    direct APRS-IS rows are deduplicated per station without mutating either
    source. On equal timestamps the Base->Field replica wins.
    """
    non_aprs: list[dict[str, Any]] = []
    replica: list[dict[str, Any]] = []
    for raw in existing_rows:
        row = dict(raw)
        if row.get("map_layer") == "aprs" or row.get("network") == "aprs":
            item = dict(row)
            item["station_id"] = str(item.get("station_id") or item.get("node_id") or "").upper()
            item["received_epoch"] = int(item.get("received_epoch") or item.get("position_epoch") or 0)
            replica.append(item)
        else:
            non_aprs.append(row)

    direct_norm: list[dict[str, Any]] = []
    for raw in direct_rows:
        item = dict(raw)
        item["station_id"] = str(item.get("station_id") or item.get("node_id") or "").upper()
        item["received_epoch"] = int(item.get("received_epoch") or item.get("position_epoch") or 0)
        direct_norm.append(item)

    merged_aprs = presentation_merge(replica, direct_norm)
    for row in merged_aprs:
        station = str(row.get("station_id") or row.get("node_id") or "").upper()
        row["node_id"] = station
        row["node_label"] = station
        row["map_layer"] = "aprs"
        row["network"] = "aprs"
        row["position_epoch"] = int(row.get("received_epoch") or row.get("position_epoch") or 0)
        if row.get("presentation_source") == "field_aprs_is":
            row["source"] = "APRS-IS / direct / receive-only"
            row["direct_aprs_is"] = True
        else:
            row["direct_aprs_is"] = False
    return sorted(
        non_aprs + merged_aprs,
        key=lambda row: (str(row.get("map_layer", "")), str(row.get("network", "")), str(row.get("node_id", ""))),
    )
