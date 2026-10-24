#!/usr/bin/env python3
"""Pure, controlled export of GuToChat position-history rows."""
from __future__ import annotations

import csv
import json
import os
import tempfile
import xml.etree.ElementTree as ET
from collections import OrderedDict
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Iterable, Mapping

from export_utils import spreadsheet_safe


EXPORT_FORMATS = ("csv", "gpx", "geojson")
EXPORT_PRECISIONS = ("reduced", "exact")
PRIVACY_DECIMAL_PLACES = 3
STORED_DECIMAL_PLACES = 7
MAX_EXPORT_ROWS = 100_000
CSV_FIELDS = (
    "network",
    "node_id",
    "node_name",
    "latitude",
    "longitude",
    "altitude_m",
    "position_time",
    "position_time_source",
    "received_at",
    "age_seconds",
    "location_source",
    "altitude_source",
    "precision_bits",
    "sats_in_view",
    "fix_quality",
    "fix_type",
    "source",
    "rx_rssi_dbm",
    "rx_snr_db",
    "export_precision",
    "exported_at",
)

_GPX_NAMESPACE = "http://www.topografix.com/GPX/1/1"
_XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"
_LORACHAT_NAMESPACE = "https://lorachat.local/xmlns/position/1"
ET.register_namespace("", _GPX_NAMESPACE)
ET.register_namespace("xsi", _XSI_NAMESPACE)
ET.register_namespace("lorachat", _LORACHAT_NAMESPACE)


class PositionExportError(ValueError):
    """Raised when position rows or export options are invalid."""


def _normalize_precision(value: str) -> str:
    precision = str(value or "").strip().lower()
    if precision not in EXPORT_PRECISIONS:
        raise PositionExportError("Eksportpresisjon må være reduced eller exact")
    return precision


def _normalize_format(value: str) -> str:
    export_format = str(value or "").strip().lower()
    if export_format not in EXPORT_FORMATS:
        raise PositionExportError("Ukjent posisjonseksportformat")
    return export_format


def _validate_export_time(value: datetime | None) -> datetime:
    exported_at = value or datetime.now().astimezone()
    if not isinstance(exported_at, datetime):
        raise PositionExportError("Eksporttid må være et datetime-objekt")
    if exported_at.tzinfo is None or exported_at.utcoffset() is None:
        raise PositionExportError("Eksporttid må inneholde tidssone")
    return exported_at


def _coordinate_text(value_i: Any, *, decimal_places: int) -> str:
    if isinstance(value_i, bool):
        raise PositionExportError("Koordinat må være et heltall")
    try:
        integer = int(value_i)
    except (TypeError, ValueError) as exc:
        raise PositionExportError("Koordinat må være et heltall") from exc
    value = Decimal(integer) / Decimal(10**STORED_DECIMAL_PLACES)
    quantum = Decimal(1).scaleb(-decimal_places)
    rounded = value.quantize(quantum, rounding=ROUND_HALF_UP)
    return format(rounded, f".{decimal_places}f")


def _epoch_iso(value: Any) -> str:
    try:
        epoch = int(value)
        if epoch < 0:
            raise ValueError
        return datetime.fromtimestamp(epoch).astimezone().isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError, OSError) as exc:
        raise PositionExportError("Posisjonstid er ugyldig") from exc


def _epoch_gpx(value: Any) -> str:
    try:
        epoch = int(value)
        if epoch < 0:
            raise ValueError
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError) as exc:
        raise PositionExportError("Posisjonstid er ugyldig") from exc


def _optional_number(value: Any) -> int | float | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise PositionExportError("Numerisk posisjonsfelt er ugyldig")
    if isinstance(value, int):
        return value
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise PositionExportError("Numerisk posisjonsfelt er ugyldig") from exc
    return int(number) if number.is_integer() else number


def _string(value: Any) -> str:
    return "" if value is None else str(value)


def build_export_records(
    rows: Iterable[Mapping[str, Any]],
    *,
    precision: str = "reduced",
    exported_at: datetime | None = None,
    max_rows: int = MAX_EXPORT_ROWS,
) -> list[dict[str, Any]]:
    """Normalize history rows into deterministic, format-neutral records."""
    selected_precision = _normalize_precision(precision)
    fixed_time = _validate_export_time(exported_at)
    if isinstance(max_rows, bool):
        raise PositionExportError("Eksportgrense må være et heltall")
    try:
        safe_limit = int(max_rows)
    except (TypeError, ValueError) as exc:
        raise PositionExportError("Eksportgrense må være et heltall") from exc
    if not 1 <= safe_limit <= MAX_EXPORT_ROWS:
        raise PositionExportError(
            f"Eksportgrense må være mellom 1 og {MAX_EXPORT_ROWS}"
        )

    materialized = list(rows)
    if not materialized:
        raise PositionExportError("Ingen posisjonspunkter er valgt")
    if len(materialized) > safe_limit:
        raise PositionExportError(
            f"Eksporten kan inneholde maksimalt {safe_limit} posisjoner"
        )

    decimal_places = (
        STORED_DECIMAL_PLACES
        if selected_precision == "exact"
        else PRIVACY_DECIMAL_PLACES
    )
    exported_epoch = int(fixed_time.timestamp())
    exported_iso = fixed_time.isoformat(timespec="seconds")
    records: list[dict[str, Any]] = []
    for row in materialized:
        network = _string(row.get("network")).strip()
        node_id = _string(row.get("node_id")).strip()
        if not network or not node_id:
            raise PositionExportError("Nettverk og node-ID må være angitt")
        latitude_i = row.get("latitude_i")
        longitude_i = row.get("longitude_i")
        try:
            latitude_integer = int(latitude_i)
            longitude_integer = int(longitude_i)
        except (TypeError, ValueError) as exc:
            raise PositionExportError("Koordinat må være et heltall") from exc
        if not -900_000_000 <= latitude_integer <= 900_000_000:
            raise PositionExportError("Breddegrad er utenfor gyldig område")
        if not -1_800_000_000 <= longitude_integer <= 1_800_000_000:
            raise PositionExportError("Lengdegrad er utenfor gyldig område")
        try:
            position_epoch = int(row.get("position_epoch"))
        except (TypeError, ValueError) as exc:
            raise PositionExportError("Posisjonstid er ugyldig") from exc
        if position_epoch < 0:
            raise PositionExportError("Posisjonstid er ugyldig")
        age_seconds = max(0, exported_epoch - position_epoch)
        record = {
            "network": network,
            "node_id": node_id,
            "node_name": _string(row.get("node_label") or row.get("node_name")),
            "latitude": _coordinate_text(
                latitude_integer, decimal_places=decimal_places
            ),
            "longitude": _coordinate_text(
                longitude_integer, decimal_places=decimal_places
            ),
            "altitude_m": _optional_number(row.get("altitude")),
            "position_time": _epoch_iso(position_epoch),
            "position_time_gpx": _epoch_gpx(position_epoch),
            "position_epoch": position_epoch,
            "position_time_source": _string(row.get("position_time_source")),
            "received_at": _string(row.get("received_at")),
            "age_seconds": age_seconds,
            "location_source": _optional_number(row.get("location_source")),
            "altitude_source": _optional_number(row.get("altitude_source")),
            "precision_bits": _optional_number(row.get("precision_bits")),
            "sats_in_view": _optional_number(row.get("sats_in_view")),
            "fix_quality": _optional_number(row.get("fix_quality")),
            "fix_type": _optional_number(row.get("fix_type")),
            "source": _string(row.get("source")),
            "rx_rssi_dbm": _optional_number(row.get("rx_rssi")),
            "rx_snr_db": _optional_number(row.get("rx_snr")),
            "export_precision": selected_precision,
            "exported_at": exported_iso,
        }
        records.append(record)
    records.sort(
        key=lambda item: (
            item["network"],
            item["node_id"],
            item["position_epoch"],
        )
    )
    return records


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, target)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _csv_bytes(records: list[dict[str, Any]]) -> bytes:
    import io

    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, delimiter=",", lineterminator="\n")
    writer.writerow(CSV_FIELDS)
    protected_text_fields = {
        "network",
        "node_id",
        "node_name",
        "position_time_source",
        "received_at",
        "source",
        "export_precision",
        "exported_at",
    }
    for record in records:
        writer.writerow(
            [
                spreadsheet_safe(record.get(field, ""))
                if field in protected_text_fields
                else record.get(field, "")
                for field in CSV_FIELDS
            ]
        )
    return ("\ufeff" + buffer.getvalue()).encode("utf-8")


def _gpx_extension(parent: ET.Element, name: str, value: Any) -> None:
    if value in (None, ""):
        return
    child = ET.SubElement(parent, f"{{{_LORACHAT_NAMESPACE}}}{name}")
    child.text = str(value)


def _gpx_bytes(records: list[dict[str, Any]]) -> bytes:
    root = ET.Element(
        f"{{{_GPX_NAMESPACE}}}gpx",
        {
            "version": "1.1",
            "creator": "GuToChat",
            f"{{{_XSI_NAMESPACE}}}schemaLocation": (
                f"{_GPX_NAMESPACE} "
                "http://www.topografix.com/GPX/1/1/gpx.xsd"
            ),
        },
    )
    metadata = ET.SubElement(root, f"{{{_GPX_NAMESPACE}}}metadata")
    ET.SubElement(metadata, f"{{{_GPX_NAMESPACE}}}time").text = records[0][
        "exported_at"
    ]
    metadata_extensions = ET.SubElement(
        metadata, f"{{{_GPX_NAMESPACE}}}extensions"
    )
    _gpx_extension(
        metadata_extensions, "export_precision", records[0]["export_precision"]
    )

    grouped: OrderedDict[tuple[str, str], list[dict[str, Any]]] = OrderedDict()
    for record in records:
        grouped.setdefault((record["network"], record["node_id"]), []).append(record)
    for (network, node_id), points in grouped.items():
        track = ET.SubElement(root, f"{{{_GPX_NAMESPACE}}}trk")
        display_name = points[0].get("node_name") or node_id
        ET.SubElement(track, f"{{{_GPX_NAMESPACE}}}name").text = (
            f"{display_name} ({network})"
        )
        track_extensions = ET.SubElement(
            track, f"{{{_GPX_NAMESPACE}}}extensions"
        )
        _gpx_extension(track_extensions, "network", network)
        _gpx_extension(track_extensions, "node_id", node_id)
        _gpx_extension(track_extensions, "node_name", points[0].get("node_name"))
        segment = ET.SubElement(track, f"{{{_GPX_NAMESPACE}}}trkseg")
        for record in points:
            point = ET.SubElement(
                segment,
                f"{{{_GPX_NAMESPACE}}}trkpt",
                {"lat": record["latitude"], "lon": record["longitude"]},
            )
            if record["altitude_m"] is not None:
                ET.SubElement(point, f"{{{_GPX_NAMESPACE}}}ele").text = str(
                    record["altitude_m"]
                )
            ET.SubElement(point, f"{{{_GPX_NAMESPACE}}}time").text = record[
                "position_time_gpx"
            ]
            extensions = ET.SubElement(
                point, f"{{{_GPX_NAMESPACE}}}extensions"
            )
            for field in (
                "position_time_source",
                "received_at",
                "age_seconds",
                "location_source",
                "altitude_source",
                "precision_bits",
                "sats_in_view",
                "fix_quality",
                "fix_type",
                "source",
                "rx_rssi_dbm",
                "rx_snr_db",
            ):
                _gpx_extension(extensions, field, record.get(field))
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _geojson_bytes(records: list[dict[str, Any]]) -> bytes:
    features: list[dict[str, Any]] = []
    for record in records:
        coordinates: list[int | float] = [
            float(record["longitude"]),
            float(record["latitude"]),
        ]
        if record["altitude_m"] is not None:
            coordinates.append(record["altitude_m"])
        properties = {
            field: record[field]
            for field in CSV_FIELDS
            if field not in {"latitude", "longitude", "altitude_m"}
        }
        properties["altitude_m"] = record["altitude_m"]
        features.append(
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": coordinates},
                "properties": properties,
            }
        )
    payload = {
        "type": "FeatureCollection",
        "properties": {
            "creator": "GuToChat",
            "export_precision": records[0]["export_precision"],
            "exported_at": records[0]["exported_at"],
        },
        "features": features,
    }
    return (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def write_position_export(
    path: Path,
    rows: Iterable[Mapping[str, Any]],
    *,
    export_format: str,
    precision: str = "reduced",
    exported_at: datetime | None = None,
    max_rows: int = MAX_EXPORT_ROWS,
) -> int:
    """Validate rows and atomically write one controlled position export file."""
    selected_format = _normalize_format(export_format)
    records = build_export_records(
        rows,
        precision=precision,
        exported_at=exported_at,
        max_rows=max_rows,
    )
    if selected_format == "csv":
        payload = _csv_bytes(records)
    elif selected_format == "gpx":
        payload = _gpx_bytes(records)
    else:
        payload = _geojson_bytes(records)
    _atomic_write_bytes(Path(path), payload)
    return len(records)
