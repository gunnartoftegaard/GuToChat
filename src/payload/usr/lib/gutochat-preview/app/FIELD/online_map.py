#!/usr/bin/env python3
"""Bounded online OSM viewport helpers for the R2-D.1 candidate.

This module keeps online-map network activity explicit and isolated. Importing
it, constructing a viewport, filtering rows or planning tiles performs no
network or database writes. Tile requests are limited to the current visible
viewport, use HTTPS, send an application User-Agent and use a local cache with
a minimum seven-day TTL. There is deliberately no prefetch/download-area API.
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import re
import time
import urllib.error
import urllib.request
from email.utils import parsedate_to_datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

try:
    from PIL import Image  # type: ignore
except Exception:  # pragma: no cover
    Image = None  # type: ignore[assignment]

TILE_SIZE = 256
MIN_ZOOM = 2
MAX_ZOOM = 18
MAX_VIEWPORT_TILES = 64
MAX_LATITUDE = 85.05112878
DEFAULT_TILE_URL_TEMPLATE = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
DEFAULT_ATTRIBUTION = "© OpenStreetMap contributors"
MIN_CACHE_SECONDS = 7 * 24 * 60 * 60
MAX_TILE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class OnlineViewport:
    center_latitude: float
    center_longitude: float
    zoom: int
    width: int
    height: int


@dataclass(frozen=True)
class TileCoordinate:
    zoom: int
    x: int
    y: int


@dataclass(frozen=True)
class TilePlacement:
    tile: TileCoordinate
    pixel_x: int
    pixel_y: int


@dataclass(frozen=True)
class OnlineMapRender:
    image: Any
    viewport: OnlineViewport
    tile_count: int
    cache_hits: int
    network_fetches: int
    attribution: str = DEFAULT_ATTRIBUTION


def _clamp_latitude(value: float) -> float:
    return max(-MAX_LATITUDE, min(MAX_LATITUDE, float(value)))


def _normalize_longitude(value: float) -> float:
    """Wrap finite longitude in bounded time; reject non-finite coordinates."""
    longitude = float(value)
    if not math.isfinite(longitude):
        raise ValueError("Longitude must be finite")
    longitude = math.fmod(longitude, 360.0)
    if longitude < -180.0:
        longitude += 360.0
    elif longitude >= 180.0:
        longitude -= 360.0
    return longitude


def normalized_viewport(viewport: OnlineViewport) -> OnlineViewport:
    zoom = max(MIN_ZOOM, min(MAX_ZOOM, int(viewport.zoom)))
    width = max(64, min(4096, int(viewport.width)))
    height = max(64, min(4096, int(viewport.height)))
    return OnlineViewport(
        center_latitude=_clamp_latitude(viewport.center_latitude),
        center_longitude=_normalize_longitude(viewport.center_longitude),
        zoom=zoom,
        width=width,
        height=height,
    )


def _world_size(zoom: int) -> float:
    return float(TILE_SIZE * (1 << int(zoom)))


def latlon_to_world_pixel(latitude: float, longitude: float, zoom: int) -> tuple[float, float]:
    lat = _clamp_latitude(latitude)
    lon = _normalize_longitude(longitude)
    size = _world_size(zoom)
    x = (lon + 180.0) / 360.0 * size
    lat_rad = math.radians(lat)
    y = (1.0 - math.asinh(math.tan(lat_rad)) / math.pi) / 2.0 * size
    return x, y


def world_pixel_to_latlon(x: float, y: float, zoom: int) -> tuple[float, float]:
    size = _world_size(zoom)
    wrapped_x = float(x) % size
    clamped_y = max(0.0, min(size, float(y)))
    lon = wrapped_x / size * 360.0 - 180.0
    n = math.pi - 2.0 * math.pi * clamped_y / size
    lat = math.degrees(math.atan(math.sinh(n)))
    return _clamp_latitude(lat), _normalize_longitude(lon)


def viewport_bounds(viewport: OnlineViewport) -> tuple[float, float, float, float]:
    """Return west,south,east,north for the visible Web-Mercator viewport.

    ``west > east`` represents an antimeridian-crossing viewport.
    """
    view = normalized_viewport(viewport)
    center_x, center_y = latlon_to_world_pixel(
        view.center_latitude, view.center_longitude, view.zoom
    )
    half_w = view.width / 2.0
    half_h = view.height / 2.0
    north, west = world_pixel_to_latlon(center_x - half_w, center_y - half_h, view.zoom)
    south, east = world_pixel_to_latlon(center_x + half_w, center_y + half_h, view.zoom)
    return west, south, east, north


def row_in_viewport(row: Mapping[str, Any], viewport: OnlineViewport) -> bool:
    try:
        lat = float(row["latitude"])
        lon = _normalize_longitude(float(row["longitude"]))
    except (KeyError, TypeError, ValueError):
        return False
    west, south, east, north = viewport_bounds(viewport)
    if not south <= lat <= north:
        return False
    if west <= east:
        return west <= lon <= east
    return lon >= west or lon <= east


def filter_rows_to_viewport(
    rows: Sequence[Mapping[str, Any]],
    viewport: OnlineViewport,
    *,
    limit: int = 500,
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 2000))
    result: list[dict[str, Any]] = []
    for row in rows:
        if row_in_viewport(row, viewport):
            result.append(dict(row))
            if len(result) >= safe_limit:
                break
    return result


def project_latlon_to_viewport(
    latitude: float,
    longitude: float,
    viewport: OnlineViewport,
) -> tuple[float, float]:
    view = normalized_viewport(viewport)
    center_x, center_y = latlon_to_world_pixel(
        view.center_latitude, view.center_longitude, view.zoom
    )
    point_x, point_y = latlon_to_world_pixel(latitude, longitude, view.zoom)
    size = _world_size(view.zoom)
    dx = point_x - center_x
    if dx > size / 2.0:
        dx -= size
    elif dx < -size / 2.0:
        dx += size
    return view.width / 2.0 + dx, view.height / 2.0 + (point_y - center_y)


def plan_viewport_tiles(
    viewport: OnlineViewport,
    *,
    max_tiles: int = MAX_VIEWPORT_TILES,
) -> list[TilePlacement]:
    """Plan only tiles intersecting the current viewport; never prefetch."""
    view = normalized_viewport(viewport)
    center_x, center_y = latlon_to_world_pixel(
        view.center_latitude, view.center_longitude, view.zoom
    )
    left = center_x - view.width / 2.0
    top = center_y - view.height / 2.0
    right = center_x + view.width / 2.0 - 1.0
    bottom = center_y + view.height / 2.0 - 1.0
    min_x = math.floor(left / TILE_SIZE)
    max_x = math.floor(right / TILE_SIZE)
    min_y = math.floor(top / TILE_SIZE)
    max_y = math.floor(bottom / TILE_SIZE)
    scale = 1 << view.zoom
    placements: list[TilePlacement] = []
    for tile_y in range(min_y, max_y + 1):
        if tile_y < 0 or tile_y >= scale:
            continue
        for raw_x in range(min_x, max_x + 1):
            tile_x = raw_x % scale
            placements.append(
                TilePlacement(
                    TileCoordinate(view.zoom, tile_x, tile_y),
                    int(round(raw_x * TILE_SIZE - left)),
                    int(round(tile_y * TILE_SIZE - top)),
                )
            )
    if len(placements) > max(1, int(max_tiles)):
        raise ValueError(
            f"viewport requires {len(placements)} tiles; maximum is {int(max_tiles)}"
        )
    return placements


def _validated_tile(tile: TileCoordinate) -> TileCoordinate:
    zoom = int(tile.zoom)
    x = int(tile.x)
    y = int(tile.y)
    if zoom < MIN_ZOOM or zoom > MAX_ZOOM:
        raise ValueError(f"online map tile zoom out of range: {zoom}")
    scale = 1 << zoom
    if x < 0 or x >= scale or y < 0 or y >= scale:
        raise ValueError(f"online map tile coordinate out of range: z={zoom} x={x} y={y}")
    return TileCoordinate(zoom, x, y)


def tile_url(tile: TileCoordinate, template: str = DEFAULT_TILE_URL_TEMPLATE) -> str:
    checked = _validated_tile(tile)
    url = str(template).format(z=checked.zoom, x=checked.x, y=checked.y)
    if not url.startswith("https://"):
        raise ValueError("online map tile URL must use HTTPS")
    return url


def _provider_cache_key(url_template: str) -> str:
    """Namespace cache entries by provider/template to prevent tile mixing."""
    return hashlib.sha256(str(url_template).encode("utf-8")).hexdigest()[:16]


def _cache_path(
    cache_directory: Path,
    tile: TileCoordinate,
    url_template: str = DEFAULT_TILE_URL_TEMPLATE,
) -> Path:
    checked = _validated_tile(tile)
    return (
        Path(cache_directory)
        / _provider_cache_key(url_template)
        / str(checked.zoom)
        / str(checked.x)
        / f"{checked.y}.png"
    )


def _metadata_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".meta.json")


def _read_metadata(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_metadata_path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _fallback_fresh_until(path: Path, *, ttl_seconds: int) -> float:
    return path.stat().st_mtime + max(MIN_CACHE_SECONDS, int(ttl_seconds))


def _read_cache_entry(
    path: Path,
    *,
    now: float,
    ttl_seconds: int,
) -> tuple[bytes | None, bool, dict[str, Any]]:
    """Return cached bytes, freshness and validator metadata if available."""
    try:
        data = path.read_bytes()
        if not data:
            return None, False, {}
        metadata = _read_metadata(path)
        try:
            fresh_until = float(metadata.get("fresh_until"))
        except (TypeError, ValueError):
            fresh_until = _fallback_fresh_until(path, ttl_seconds=ttl_seconds)
        return data, now <= fresh_until, metadata
    except OSError:
        return None, False, {}


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(dict(value), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    temporary.replace(path)


def _write_cache(path: Path, data: bytes, metadata: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(path)
    _write_json_atomic(_metadata_path(path), metadata)


def _header_value(headers: Any, name: str) -> str:
    if headers is None:
        return ""
    try:
        value = headers.get(name, "")
    except (AttributeError, TypeError):
        return ""
    return str(value or "").strip()


def _fresh_until_from_headers(headers: Any, *, now: float, ttl_seconds: int) -> float:
    """Honor HTTP freshness metadata; fall back to at least seven days."""
    cache_control = _header_value(headers, "Cache-Control")
    match = re.search(r"(?:^|,)\s*max-age\s*=\s*(\d+)", cache_control, re.I)
    if match:
        return now + max(0, int(match.group(1)))
    expires = _header_value(headers, "Expires")
    if expires:
        try:
            parsed = parsedate_to_datetime(expires)
            if parsed.tzinfo is not None:
                return parsed.timestamp()
        except (TypeError, ValueError, OverflowError):
            pass
    return now + max(MIN_CACHE_SECONDS, int(ttl_seconds))


def _response_metadata(
    headers: Any,
    *,
    now: float,
    ttl_seconds: int,
    previous: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    prior = dict(previous or {})
    etag = _header_value(headers, "ETag") or str(prior.get("etag") or "")
    last_modified = _header_value(headers, "Last-Modified") or str(
        prior.get("last_modified") or ""
    )
    result: dict[str, Any] = {
        "fresh_until": _fresh_until_from_headers(
            headers, now=now, ttl_seconds=ttl_seconds
        ),
        "validated_at": now,
    }
    if etag:
        result["etag"] = etag
    if last_modified:
        result["last_modified"] = last_modified
    return result


def fetch_osm_tile(
    tile: TileCoordinate,
    *,
    cache_directory: Path,
    user_agent: str,
    url_template: str = DEFAULT_TILE_URL_TEMPLATE,
    timeout_seconds: float = 4.0,
    cache_ttl_seconds: int = MIN_CACHE_SECONDS,
    opener: Callable[..., Any] | None = None,
    now: float | None = None,
) -> tuple[bytes, bool]:
    """Return one visible tile and whether it came from cache.

    Only the requested visible tile can be fetched. Expired cache entries use
    conditional validators when available. Response size is bounded before an
    atomic cache replacement is permitted.
    """
    checked = _validated_tile(tile)
    agent = str(user_agent).strip()
    if not agent:
        raise ValueError("online map User-Agent must identify the application")
    current = time.time() if now is None else float(now)
    path = _cache_path(Path(cache_directory), checked, url_template)
    cached_data, fresh, metadata = _read_cache_entry(
        path, now=current, ttl_seconds=cache_ttl_seconds
    )
    if cached_data is not None and fresh:
        return cached_data, True

    headers = {"User-Agent": agent, "Accept": "image/png,image/*;q=0.8"}
    if cached_data is not None:
        etag = str(metadata.get("etag") or "").strip()
        last_modified = str(metadata.get("last_modified") or "").strip()
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

    request = urllib.request.Request(
        tile_url(checked, url_template),
        headers=headers,
        method="GET",
    )
    open_url = opener or urllib.request.urlopen
    try:
        response_context = open_url(request, timeout=max(1.0, float(timeout_seconds)))
        with response_context as response:
            data = response.read(MAX_TILE_BYTES + 1)
            response_headers = getattr(response, "headers", None)
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and cached_data is not None:
            refreshed = _response_metadata(
                exc.headers,
                now=current,
                ttl_seconds=cache_ttl_seconds,
                previous=metadata,
            )
            _write_json_atomic(_metadata_path(path), refreshed)
            try:
                path.touch()
            except OSError:
                pass
            return cached_data, True
        raise

    if not data:
        raise ValueError("online map server returned an empty tile")
    if len(data) > MAX_TILE_BYTES:
        raise ValueError(
            f"online map tile exceeds maximum size of {MAX_TILE_BYTES} bytes"
        )
    response_metadata = _response_metadata(
        response_headers,
        now=current,
        ttl_seconds=cache_ttl_seconds,
    )
    _write_cache(path, data, response_metadata)
    return data, False

def render_osm_viewport(
    viewport: OnlineViewport,
    *,
    cache_directory: Path,
    user_agent: str,
    url_template: str = DEFAULT_TILE_URL_TEMPLATE,
    timeout_seconds: float = 4.0,
    fetcher: Callable[[TileCoordinate], tuple[bytes, bool]] | None = None,
) -> OnlineMapRender:
    """Render the current OSM viewport from bounded raster tile requests."""
    if Image is None:
        raise RuntimeError("Pillow is required for online raster map rendering")
    view = normalized_viewport(viewport)
    placements = plan_viewport_tiles(view)
    image = Image.new("RGB", (view.width, view.height), "white")
    cache_hits = 0
    network_fetches = 0

    for placement in placements:
        if fetcher is None:
            data, cached = fetch_osm_tile(
                placement.tile,
                cache_directory=cache_directory,
                user_agent=user_agent,
                url_template=url_template,
                timeout_seconds=timeout_seconds,
            )
        else:
            data, cached = fetcher(placement.tile)
        if cached:
            cache_hits += 1
        else:
            network_fetches += 1
        with Image.open(io.BytesIO(data)) as tile_image:
            tile_rgb = tile_image.convert("RGB")
            if tile_rgb.size != (TILE_SIZE, TILE_SIZE):
                tile_rgb = tile_rgb.resize((TILE_SIZE, TILE_SIZE))
            image.paste(tile_rgb, (placement.pixel_x, placement.pixel_y))

    return OnlineMapRender(
        image=image,
        viewport=view,
        tile_count=len(placements),
        cache_hits=cache_hits,
        network_fetches=network_fetches,
    )
