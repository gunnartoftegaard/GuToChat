#!/usr/bin/env python3
"""Read-only offline map helpers for the GuToChat Tkinter GUI.

The module deliberately has no radio, network, export or database write side
operations. SQLite databases are opened with ``mode=ro`` and MBTiles files are
opened read-only. Coordinates returned for the map tab are privacy-reduced by
rounding to three decimal degrees unless a future caller explicitly implements a
separate full-precision workflow with confirmation.

GuToChat treats maps as local data packages. The package discovery functions
inspect only regular ``.mbtiles`` files, validate a small metadata contract and
select the best package for privacy-reduced positions. They never download,
repair, modify or delete map data.
"""
from __future__ import annotations

import io
import math
import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


PRIVACY_DECIMALS = 3
MAX_MAP_HISTORY_ROWS = 1000
MAX_DISCOVERED_MAP_FILES = 256
SUPPORTED_RASTER_FORMATS = frozenset({"png"})
VALID_MAP_PACKAGE_TYPES = frozenset({"overview", "region", "mission"})
DEFAULT_MAP_PACKAGE_TYPE = "region"
DEFAULT_MAP_PRIORITIES = {
    "overview": 100,
    "region": 200,
    "mission": 300,
}
# Negative priorities are reserved for proof/validation packages.  They remain
# manually selectable and are used by AUTO only when no operational package
# exists at all.  This keeps retained A2.5 proof tiles from displacing the
# operator's real regional map merely because a proof package has world bounds.
AUTO_OPERATIONAL_MIN_PRIORITY = 0

try:  # Pillow image decoding is an optional GUI dependency for the map tab.
    from PIL import Image  # type: ignore
except Exception:  # pragma: no cover - exercised on machines without Pillow.
    Image = None  # type: ignore[assignment]

try:  # ImageTk may be packaged separately from Pillow on some Linux systems.
    from PIL import ImageTk  # type: ignore
except Exception:  # pragma: no cover - exercised on machines without ImageTk.
    ImageTk = None  # type: ignore[assignment]


@dataclass(frozen=True)
class MapStatus:
    """Resolved state for the active offline map file."""

    path: Path | None
    state: str
    message: str


@dataclass(frozen=True)
class MapPackage:
    """Validated metadata for one local raster MBTiles package."""

    path: Path
    name: str
    bounds: tuple[float, float, float, float]
    min_zoom: int
    max_zoom: int
    image_format: str
    attribution: str
    package_type: str
    priority: int

    @property
    def geographic_area(self) -> float:
        """Return a deterministic approximate bounds area in square degrees."""
        west, south, east, north = self.bounds
        longitude_span = east - west if west <= east else (180.0 - west) + (east + 180.0)
        return max(0.0, longitude_span) * max(0.0, north - south)


@dataclass(frozen=True)
class TileImage:
    """Decoded MBTiles raster tile and its XYZ coordinate."""

    zoom: int
    x: int
    y: int
    image: Any | None
    data: bytes = b""


def resolve_database_path(config: Mapping[str, Any]) -> Path:
    """Return the active GuToChat database path from config.json."""
    value = str(config.get("database") or "").strip()
    if not value:
        raise ValueError("config.json mangler feltet database")
    return Path(value).expanduser()


def _default_data_home() -> Path:
    """Return an XDG-compatible per-user data directory."""
    raw = os.environ.get("XDG_DATA_HOME", "").strip()
    return Path(raw).expanduser() if raw else Path.home() / ".local" / "share"


def resolve_offline_map_directory(config: Mapping[str, Any]) -> Path:
    """Return the configured map package directory or the GuToChat XDG default."""
    raw = str(config.get("offline_map_directory") or "").strip()
    if raw:
        return Path(raw).expanduser()
    return _default_data_home() / "gutochat" / "maps"


def resolve_offline_map_path(config: Mapping[str, Any]) -> MapStatus:
    """Return a safe status object for the legacy offline_map_path setting."""
    raw = str(config.get("offline_map_path") or "").strip()
    if not raw:
        return MapStatus(
            None,
            "not_configured",
            "Ingen offline kartfil er konfigurert.",
        )
    path = Path(raw).expanduser()
    if not path.exists():
        return MapStatus(path, "missing", f"Kartfilen finnes ikke: {path}")
    if not path.is_file():
        return MapStatus(path, "invalid", f"Kartbanen er ikke en fil: {path}")
    return MapStatus(path, "ready", f"Offline kartfil: {path}")


def privacy_reduce_degrees(value: Any) -> float:
    """Return a three-decimal degree value for privacy-safe map display."""
    return round(float(value), PRIVACY_DECIMALS)


def _row_to_privacy_dict(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    latitude = int(row["latitude_i"]) / 10_000_000.0
    longitude = int(row["longitude_i"]) / 10_000_000.0
    value["latitude"] = privacy_reduce_degrees(latitude)
    value["longitude"] = privacy_reduce_degrees(longitude)
    return value


def read_latest_positions_read_only(
    database_path: Path,
    *,
    network: str | None = None,
) -> list[dict[str, Any]]:
    """Read latest positions from the active database without writing."""
    clauses: list[str] = []
    params: list[Any] = []
    if network:
        clauses.append("network = ?")
        params.append(str(network))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with sqlite3.connect(f"file:{Path(database_path)}?mode=ro", uri=True) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT * FROM node_positions_latest"
            f"{where} ORDER BY network, node_id",
            params,
        ).fetchall()
    return [_row_to_privacy_dict(row) for row in rows]


def read_position_history_read_only(
    database_path: Path,
    *,
    network: str | None = None,
    node_id: str | None = None,
    limit: int = 250,
) -> list[dict[str, Any]]:
    """Read a bounded newest-first position history without writing."""
    safe_limit = max(1, min(int(limit), MAX_MAP_HISTORY_ROWS))
    clauses: list[str] = []
    params: list[Any] = []
    if network:
        clauses.append("network = ?")
        params.append(str(network))
    if node_id:
        clauses.append("node_id = ?")
        params.append(str(node_id))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with sqlite3.connect(f"file:{Path(database_path)}?mode=ro", uri=True) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT * FROM node_positions_history"
            f"{where} ORDER BY sequence DESC LIMIT ?",
            (*params, safe_limit),
        ).fetchall()
    return [_row_to_privacy_dict(row) for row in rows]


def read_mbtiles_metadata(path: Path) -> dict[str, str]:
    """Read MBTiles metadata from a local file without writing."""
    with sqlite3.connect(f"file:{Path(path)}?mode=ro", uri=True) as con:
        rows = con.execute("SELECT name, value FROM metadata").fetchall()
    return {str(name): str(value) for name, value in rows}


def _parse_bounds(value: str) -> tuple[float, float, float, float]:
    """Parse and validate MBTiles bounds as west,south,east,north."""
    parts = [part.strip() for part in str(value).split(",")]
    if len(parts) != 4:
        raise ValueError("metadatafeltet bounds må ha fire kommaseparerte verdier")
    try:
        west, south, east, north = (float(part) for part in parts)
    except ValueError as exc:
        raise ValueError("metadatafeltet bounds inneholder ugyldige tall") from exc
    if not all(math.isfinite(value) for value in (west, south, east, north)):
        raise ValueError("metadatafeltet bounds inneholder ikke-endelige tall")
    if not (-180.0 <= west <= 180.0 and -180.0 <= east <= 180.0):
        raise ValueError("metadatafeltet bounds har ugyldig lengdegrad")
    if not (-90.0 <= south <= 90.0 and -90.0 <= north <= 90.0):
        raise ValueError("metadatafeltet bounds har ugyldig breddegrad")
    if south > north:
        raise ValueError("metadatafeltet bounds har south større enn north")
    return west, south, east, north


def _parse_zoom(metadata: Mapping[str, str], name: str) -> int:
    """Return one validated MBTiles zoom metadata value."""
    raw = str(metadata.get(name, "")).strip()
    if not raw:
        raise ValueError(f"metadatafeltet {name} mangler")
    try:
        numeric_zoom = float(raw)
    except ValueError as exc:
        raise ValueError(f"metadatafeltet {name} er ugyldig") from exc
    if not math.isfinite(numeric_zoom) or not numeric_zoom.is_integer():
        raise ValueError(f"metadatafeltet {name} må være et heltall")
    zoom = int(numeric_zoom)
    if not 0 <= zoom <= 18:
        raise ValueError(f"metadatafeltet {name} må være mellom 0 og 18")
    return zoom


def read_map_package(path: Path) -> MapPackage:
    """Validate and return metadata for one local PNG MBTiles package.

    The file is opened read-only. A package used for automatic selection must
    declare name, format, bounds, minzoom, maxzoom and attribution. Optional
    GuToChat metadata controls package type and selection priority.
    """
    map_path = Path(path)
    try:
        mode = map_path.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"kartfilen kan ikke undersøkes: {map_path}") from exc
    if not stat.S_ISREG(mode):
        raise ValueError(f"kartbanen er ikke en regulær fil: {map_path}")
    if map_path.suffix.casefold() != ".mbtiles":
        raise ValueError(f"kartfilen har ikke endelsen .mbtiles: {map_path}")

    metadata = read_mbtiles_metadata(map_path)
    name = str(metadata.get("name", "")).strip()
    image_format = str(metadata.get("format", "")).strip().casefold()
    attribution = str(metadata.get("attribution", "")).strip()
    if not name:
        raise ValueError("metadatafeltet name mangler")
    if image_format not in SUPPORTED_RASTER_FORMATS:
        raise ValueError("metadatafeltet format må være png")
    if not attribution:
        raise ValueError("metadatafeltet attribution mangler")

    bounds = _parse_bounds(metadata.get("bounds", ""))
    min_zoom = _parse_zoom(metadata, "minzoom")
    max_zoom = _parse_zoom(metadata, "maxzoom")
    if min_zoom > max_zoom:
        raise ValueError("metadatafeltet minzoom er større enn maxzoom")

    package_type = str(
        metadata.get("gutochat_type", DEFAULT_MAP_PACKAGE_TYPE)
    ).strip().casefold()
    if package_type not in VALID_MAP_PACKAGE_TYPES:
        raise ValueError(
            "metadatafeltet gutochat_type må være overview, region eller mission"
        )
    priority_raw = str(metadata.get("gutochat_priority", "")).strip()
    if priority_raw:
        try:
            priority = int(priority_raw)
        except ValueError as exc:
            raise ValueError("metadatafeltet gutochat_priority er ugyldig") from exc
    else:
        priority = DEFAULT_MAP_PRIORITIES[package_type]
    if not -10_000 <= priority <= 10_000:
        raise ValueError("metadatafeltet gutochat_priority er utenfor tillatt område")

    return MapPackage(
        path=map_path,
        name=name,
        bounds=bounds,
        min_zoom=min_zoom,
        max_zoom=max_zoom,
        image_format=image_format,
        attribution=attribution,
        package_type=package_type,
        priority=priority,
    )


def _iter_regular_mbtiles(
    directory: Path,
    *,
    max_files: int = MAX_DISCOVERED_MAP_FILES,
) -> list[Path]:
    """Return deterministic regular MBTiles paths without following symlinks."""
    root = Path(directory)
    try:
        root_mode = root.lstat().st_mode
    except OSError:
        return []
    if not stat.S_ISDIR(root_mode):
        return []

    paths: list[Path] = []
    safe_limit = max(0, min(int(max_files), MAX_DISCOVERED_MAP_FILES))
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if not (current_path / name).is_symlink()
        )
        for name in sorted(file_names):
            if len(paths) >= safe_limit:
                return paths
            path = current_path / name
            if path.suffix.casefold() != ".mbtiles":
                continue
            try:
                mode = path.lstat().st_mode
            except OSError:
                continue
            if stat.S_ISREG(mode):
                paths.append(path)
    return paths


def discover_map_packages(
    directory: Path,
    *,
    max_files: int = MAX_DISCOVERED_MAP_FILES,
) -> list[MapPackage]:
    """Return valid local map packages; invalid files are safely ignored."""
    packages: list[MapPackage] = []
    for path in _iter_regular_mbtiles(directory, max_files=max_files):
        try:
            packages.append(read_map_package(path))
        except (OSError, sqlite3.Error, ValueError):
            # A broken optional map package must not disable chat or radio.
            continue
    return packages


def offline_map_sources_signature(config: Mapping[str, Any]) -> tuple[Any, ...]:
    """Return a small read-only signature for map-source refresh detection."""
    directory = resolve_offline_map_directory(config)
    entries: list[tuple[str, int, int]] = []
    for path in _iter_regular_mbtiles(directory):
        try:
            file_stat = path.stat()
            entries.append(
                (
                    str(path.relative_to(directory)),
                    int(file_stat.st_size),
                    int(file_stat.st_mtime_ns),
                )
            )
        except OSError:
            continue

    legacy = resolve_offline_map_path(config)
    legacy_signature: tuple[Any, ...] = (legacy.state, str(legacy.path or ""))
    if legacy.state == "ready" and legacy.path is not None:
        try:
            file_stat = legacy.path.stat()
            legacy_signature += (int(file_stat.st_size), int(file_stat.st_mtime_ns))
        except OSError:
            legacy_signature += ("unreadable",)
    return (str(directory), tuple(entries), legacy_signature)


def package_covers_position(
    package: MapPackage,
    latitude: float,
    longitude: float,
) -> bool:
    """Return whether a package contains one privacy-reduced position."""
    west, south, east, north = package.bounds
    if not south <= latitude <= north:
        return False
    if west <= east:
        return west <= longitude <= east
    # Bounds crossing the antimeridian are represented with west > east.
    return longitude >= west or longitude <= east


def filter_aprs_rows_to_package_coverage(
    rows: Sequence[Mapping[str, Any]],
    package: MapPackage | None,
) -> list[dict[str, Any]]:
    """Return presentation rows with APRS markers limited to MBTiles coverage.

    Non-APRS rows are intentionally preserved. APRS rows fail closed when no
    validated package is available or when their reduced coordinates are
    invalid/outside the package bounds. This function only filters in-memory
    presentation data; it never mutates provider/store rows.
    """
    visible: list[dict[str, Any]] = []
    for source_row in rows:
        row = dict(source_row)
        if row.get("map_layer") != "aprs":
            visible.append(row)
            continue
        if package is None:
            continue
        try:
            latitude = privacy_reduce_degrees(row["latitude"])
            longitude = privacy_reduce_degrees(row["longitude"])
        except (KeyError, TypeError, ValueError):
            continue
        if package_covers_position(package, latitude, longitude):
            visible.append(row)
    return visible


# Backward-compatible private alias for existing internal callers/tests.
_package_covers_position = package_covers_position


def _selection_points(rows: Sequence[Mapping[str, Any]]) -> list[tuple[float, float]]:
    """Return reduced center-first positions used only for local map selection."""
    points: list[tuple[float, float]] = []
    for row in rows:
        try:
            latitude = privacy_reduce_degrees(row["latitude"])
            longitude = privacy_reduce_degrees(row["longitude"])
        except (KeyError, TypeError, ValueError):
            continue
        point = (latitude, longitude)
        if point not in points:
            points.append(point)
    if not points:
        return []
    center = (
        privacy_reduce_degrees(sum(point[0] for point in points) / len(points)),
        privacy_reduce_degrees(sum(point[1] for point in points) / len(points)),
    )
    return [center] + [point for point in points if point != center]


def _package_sort_key(package: MapPackage) -> tuple[Any, ...]:
    """Return deterministic best-first selection order for map packages."""
    return (
        -package.priority,
        -package.max_zoom,
        package.geographic_area,
        str(package.path).casefold(),
    )


def select_map_package(
    packages: Sequence[MapPackage],
    rows: Sequence[Mapping[str, Any]],
) -> MapPackage | None:
    """Select the best automatic package with operational maps preferred.

    Packages with negative priority are retained proof/validation packages.
    When one or more operational packages (priority >= 0) exist, AUTO never
    lets a negative-priority proof package win merely because it has broader
    bounds.  Coverage is still preferred among operational packages; when the
    current reduced positions are outside every operational package, the
    highest-priority operational package becomes the stable AUTO default.

    If a deployment contains only proof packages, the historical coverage
    behavior is preserved so diagnostics/test installations remain usable.
    """
    operational = [
        package for package in packages
        if package.priority >= AUTO_OPERATIONAL_MIN_PRIORITY
    ]
    proof = [
        package for package in packages
        if package.priority < AUTO_OPERATIONAL_MIN_PRIORITY
    ]

    for latitude, longitude in _selection_points(rows):
        operational_matches = [
            package
            for package in operational
            if _package_covers_position(package, latitude, longitude)
        ]
        if operational_matches:
            return sorted(operational_matches, key=_package_sort_key)[0]

        proof_matches = [
            package
            for package in proof
            if _package_covers_position(package, latitude, longitude)
        ]
        if proof_matches:
            # Retained proof/validation packages must not displace a real map.
            # When a proof package would otherwise win solely because it has
            # broader bounds, use the best operational package as the stable
            # AUTO default.  If no operational package exists, preserve the
            # historic proof-only behavior.
            if operational:
                return sorted(operational, key=_package_sort_key)[0]
            return sorted(proof_matches, key=_package_sort_key)[0]

    return None


def resolve_active_map(
    config: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> MapStatus:
    """Resolve the best discovered map, then fall back to offline_map_path."""
    directory = resolve_offline_map_directory(config)
    packages = discover_map_packages(directory)
    selected = select_map_package(packages, rows)
    if selected is not None:
        return MapStatus(
            selected.path,
            "ready",
            f"Automatisk valgt kart: {selected.name}",
        )

    legacy = resolve_offline_map_path(config)
    if legacy.state == "ready":
        return MapStatus(
            legacy.path,
            "ready",
            f"Kompatibilitetskart: {legacy.path}",
        )
    if packages and rows:
        return MapStatus(
            None,
            "no_coverage",
            "Ingen lokal kartpakke dekker de valgte posisjonene.",
        )
    if not directory.exists() and legacy.state == "not_configured":
        return MapStatus(
            None,
            "not_configured",
            f"Ingen kartkatalog eller offline kartfil er konfigurert: {directory}",
        )
    return legacy


def _lon_to_tile_x(longitude: float, zoom: int) -> int:
    scale = 1 << zoom
    return int((longitude + 180.0) / 360.0 * scale)


def _lat_to_tile_y(latitude: float, zoom: int) -> int:
    lat_rad = math.radians(max(min(latitude, 85.05112878), -85.05112878))
    scale = 1 << zoom
    return int(
        (1.0 - math.log(math.tan(lat_rad) + 1.0 / math.cos(lat_rad)) / math.pi)
        / 2.0
        * scale
    )


def tile_for_center(latitude: float, longitude: float, zoom: int) -> tuple[int, int, int]:
    """Return one validated XYZ tile coordinate for an explicit local viewport."""
    latitude = float(latitude)
    longitude = float(longitude)
    if not math.isfinite(latitude) or not math.isfinite(longitude):
        raise ValueError("kartviewport krever endelige koordinater")
    if not -85.05112878 <= latitude <= 85.05112878:
        raise ValueError("kartviewport breddegrad må være mellom -85.05112878 og 85.05112878")
    if not -180.0 <= longitude <= 180.0:
        raise ValueError("kartviewport lengdegrad må være mellom -180 og 180")
    if isinstance(zoom, bool):
        raise ValueError("kartviewport zoom må være et heltall mellom 0 og 18")
    try:
        numeric_zoom = int(zoom)
    except (TypeError, ValueError) as exc:
        raise ValueError("kartviewport zoom må være et heltall mellom 0 og 18") from exc
    if numeric_zoom != zoom or not 0 <= numeric_zoom <= 18:
        raise ValueError("kartviewport zoom må være et heltall mellom 0 og 18")
    return (
        numeric_zoom,
        _lon_to_tile_x(longitude, numeric_zoom),
        _lat_to_tile_y(latitude, numeric_zoom),
    )


def load_raster_tile_for_center(
    path: Path,
    latitude: float,
    longitude: float,
    zoom: int,
) -> TileImage | None:
    """Load one local read-only MBTiles tile for an explicit center/zoom."""
    tile_zoom, x, y = tile_for_center(latitude, longitude, zoom)
    return load_raster_tile(path, tile_zoom, x, y)


def _xyz_to_tms_y(y: int, zoom: int) -> int:
    return (1 << zoom) - 1 - y


def choose_tile_for_positions(
    rows: list[Mapping[str, Any]],
    metadata: Mapping[str, str],
) -> tuple[int, int, int] | None:
    """Return an XYZ tile coordinate covering the reduced center point."""
    if not rows:
        return None
    zoom_text = metadata.get("maxzoom") or metadata.get("zoom") or metadata.get("minzoom")
    try:
        zoom = max(0, min(int(float(str(zoom_text))), 18)) if zoom_text else 12
    except (TypeError, ValueError):
        zoom = 12
    latitude = sum(float(row["latitude"]) for row in rows) / len(rows)
    longitude = sum(float(row["longitude"]) for row in rows) / len(rows)
    return zoom, _lon_to_tile_x(longitude, zoom), _lat_to_tile_y(latitude, zoom)


def _read_tile_data(path: Path, zoom: int, x: int, tile_row: int) -> bytes | None:
    """Return one MBTiles tile blob using a read-only SQLite connection."""
    with sqlite3.connect(f"file:{Path(path)}?mode=ro", uri=True) as con:
        row = con.execute(
            "SELECT tile_data FROM tiles WHERE zoom_level = ? "
            "AND tile_column = ? AND tile_row = ?",
            (zoom, x, tile_row),
        ).fetchone()
    return bytes(row[0]) if row is not None else None


def _decode_tile_data(data: bytes) -> Any | None:
    """Decode one PNG/JPEG raster tile, if Pillow can read it."""
    if Image is None:
        return None
    try:
        return Image.open(io.BytesIO(data)).convert("RGB")
    except Exception:
        return None


def load_raster_tile(path: Path, zoom: int, x: int, y: int) -> TileImage | None:
    """Decode one raster tile from MBTiles using TMS first and XYZ fallback.

    The MBTiles specification commonly stores ``tile_row`` in TMS order, while
    many tile calculations produce XYZ rows. GuToChat keeps both conventions
    local and read-only: it first tries the TMS-converted row and then falls
    back to the original XYZ row when no TMS tile exists.
    """
    for tile_row in (_xyz_to_tms_y(y, zoom), y):
        data = _read_tile_data(path, zoom, x, tile_row)
        if data is None:
            continue
        image = _decode_tile_data(data)
        # Keep valid PNG/JPEG bytes even when Pillow decoding is unavailable.
        # The Tkinter GUI can use this as a native PhotoImage fallback.
        if image is not None or data:
            return TileImage(zoom=zoom, x=x, y=y, image=image, data=data)
    return None


def _metadata_zoom_range(metadata: Mapping[str, str]) -> tuple[int, int]:
    """Return a safe min/max zoom range from MBTiles metadata."""

    def parse_zoom(name: str, fallback: int) -> int:
        try:
            return max(0, min(int(float(str(metadata.get(name, fallback)))), 18))
        except (TypeError, ValueError):
            return fallback

    max_zoom = parse_zoom("maxzoom", parse_zoom("zoom", 12))
    min_zoom = parse_zoom("minzoom", max_zoom)
    if min_zoom > max_zoom:
        min_zoom = max_zoom
    return min_zoom, max_zoom


def _tile_candidates_for_rows(
    rows: list[Mapping[str, Any]],
    metadata: Mapping[str, str],
) -> list[tuple[int, int, int]]:
    """Return privacy-reduced XYZ tile candidates for the map preview."""
    if not rows:
        return []
    min_zoom, max_zoom = _metadata_zoom_range(metadata)
    candidates: list[tuple[int, int, int]] = []

    def append_for_point(latitude: float, longitude: float) -> None:
        for zoom in range(max_zoom, min_zoom - 1, -1):
            item = (zoom, _lon_to_tile_x(longitude, zoom), _lat_to_tile_y(latitude, zoom))
            if item not in candidates:
                candidates.append(item)

    # Try the center first for a stable preview, then every individual point.
    center_latitude = sum(float(row["latitude"]) for row in rows) / len(rows)
    center_longitude = sum(float(row["longitude"]) for row in rows) / len(rows)
    append_for_point(center_latitude, center_longitude)
    for row in rows:
        append_for_point(float(row["latitude"]), float(row["longitude"]))
    return candidates


def load_default_raster_tile(
    path: Path,
    metadata: Mapping[str, str],
) -> TileImage | None:
    """Load a deterministic package-center preview tile read-only.

    This is used only as an AUTO presentation fallback when an operational
    package exists but the current position set lies outside its bounds.  An
    explicit/manual viewport never uses this fallback.
    """
    try:
        west, south, east, north = _parse_bounds(str(metadata.get("bounds", "")))
    except ValueError:
        return None
    if west <= east:
        longitude = (west + east) / 2.0
    else:
        span = (180.0 - west) + (east + 180.0)
        longitude = west + (span / 2.0)
        if longitude > 180.0:
            longitude -= 360.0
    latitude = (south + north) / 2.0
    min_zoom, max_zoom = _metadata_zoom_range(metadata)
    for zoom in range(max_zoom, min_zoom - 1, -1):
        tile = load_raster_tile_for_center(path, latitude, longitude, zoom)
        if tile is not None:
            return tile
    return None


def load_best_raster_tile(
    path: Path,
    rows: list[Mapping[str, Any]],
    metadata: Mapping[str, str],
) -> TileImage | None:
    """Load the first available local raster tile for the reduced positions."""
    for zoom, x, y in _tile_candidates_for_rows(rows, metadata):
        tile = load_raster_tile(path, zoom, x, y)
        if tile is not None:
            return tile
    return None
