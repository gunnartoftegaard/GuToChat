from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from offline_map import (
    MapPackage,
    MapStatus,
    discover_map_packages,
    resolve_active_map,
    resolve_offline_map_directory,
)

AUTO_MAP_KEY = "__AUTO__"


@dataclass(frozen=True)
class OperatorMapEntry:
    """One validated, read-only MBTiles choice for operator presentation."""

    key: str
    label: str
    package: MapPackage


def _relative_key(root: Path, path: Path) -> str:
    """Return a stable path identity without resolving/following symlinks."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def build_operator_map_inventory(config: Mapping[str, Any]) -> list[OperatorMapEntry]:
    """Return deterministic validated MBTiles choices without writing anything."""
    root = resolve_offline_map_directory(config)
    packages = discover_map_packages(root)
    return [
        OperatorMapEntry(
            key=_relative_key(root, package.path),
            label=f"{package.name} — {_relative_key(root, package.path)}",
            package=package,
        )
        for package in packages
    ]


def resolve_operator_map(
    config: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    selected_key: str,
) -> MapStatus:
    """Resolve AUTO or one exact validated operator choice, fail-closed if stale."""
    key = str(selected_key or AUTO_MAP_KEY)
    if key == AUTO_MAP_KEY:
        return resolve_active_map(config, rows)
    for entry in build_operator_map_inventory(config):
        if entry.key == key:
            return MapStatus(entry.package.path, "ready", f"Operatørvalgt kart: {entry.package.name}")
    return MapStatus(None, "selection_unavailable", f"Valgt kart er ikke lenger tilgjengelig eller gyldig: {key}")


def operator_map_metadata_text(entry: OperatorMapEntry) -> str:
    """Render bounded local metadata for the GUI; no network or filesystem writes."""
    p = entry.package
    west, south, east, north = p.bounds
    return (
        f"{p.name} • {entry.key} • bounds {west:g},{south:g},{east:g},{north:g} • "
        f"zoom {p.min_zoom}–{p.max_zoom} • {p.image_format} • type {p.package_type} • "
        f"priority {p.priority} • {p.attribution}"
    )
