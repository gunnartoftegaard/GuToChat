#!/usr/bin/env python3
"""R2-E.A2-A1 isolated Field APRS-IS presentation source.

Architecture contract:
- disabled by default; no network side effect at construction/startup
- direct APRS-IS is receive-only and uses the existing Base APRS-IS client
- direct APRS-IS persists only to its own dedicated cache DB
- never writes to Field's Base->Field APRS replica DB
- merge/deduplication is presentation-only and preserves source provenance
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Any

from aprs_is_client import AprsIsClient, AprsIsConfig
from aprs_parser import parse_tnc2_line
from aprs_store import AprsStore

DEFAULT_CACHE_NAME = "aprs-is-presentation.sqlite3"
FORBIDDEN_REPLICA_NAMES = {"aprs-replica.sqlite3", "aprs_replica.sqlite3"}


@dataclass(frozen=True)
class FieldAprsIsPresentationConfig:
    login: str
    range_filter: str
    cache_db: Path
    enabled: bool = False

    def __post_init__(self) -> None:
        p = Path(self.cache_db)
        if p.name.lower() in FORBIDDEN_REPLICA_NAMES:
            raise ValueError("Direct APRS-IS cache must not use the Field APRS replica DB")
        object.__setattr__(self, "cache_db", p)

    def aprs_is_config(self) -> AprsIsConfig:
        return AprsIsConfig(login=self.login, range_filter=self.range_filter)


class FieldAprsIsPresentationSource:
    """Separate optional APRS-IS presentation source; OFF unless enabled."""

    def __init__(self, config: FieldAprsIsPresentationConfig) -> None:
        self.config = config
        self._store: AprsStore | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled)

    @property
    def store(self) -> AprsStore:
        # DB creation itself is delayed until explicitly used.
        if self._store is None:
            self._store = AprsStore(self.config.cache_db)
        return self._store

    def build_live_client(self, **kwargs: Any) -> AprsIsClient:
        """Return live receive-only client only after explicit enablement."""
        if not self.enabled:
            raise RuntimeError("Field direct APRS-IS is OFF; explicit enablement required")
        return AprsIsClient(self.config.aprs_is_config(), self.store, **kwargs)

    def ingest_fixture_line(self, line: str, *, received_at: str) -> str:
        """Offline-only fixture ingress used for isolated tests; no socket involved."""
        packet = parse_tnc2_line(
            line,
            source_type="aprs_is",
            transport="unknown",
            received_at=received_at,
        )
        return self.store.store_packet(packet)


def presentation_merge(
    replica_rows: Iterable[Mapping[str, Any]],
    aprs_is_rows: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Merge for display without changing either underlying data source.

    One row per station is selected. Existing Base->Field RF replica wins ties or
    newer/equal observations because it remains the preferred local-RF view.
    APRS-IS may fill a station absent from the replica or provide a strictly newer
    presentation observation. Provenance is always retained.
    """
    chosen: dict[str, dict[str, Any]] = {}

    def normalize(row: Mapping[str, Any], source: str) -> dict[str, Any]:
        out = dict(row)
        station = str(out.get("station_id") or out.get("node") or "").strip().upper()
        if not station:
            raise ValueError("presentation row missing station_id")
        out["station_id"] = station
        out["presentation_source"] = source
        out["received_epoch"] = int(out.get("received_epoch") or 0)
        return out

    for raw in aprs_is_rows:
        row = normalize(raw, "field_aprs_is")
        chosen[row["station_id"]] = row

    for raw in replica_rows:
        row = normalize(raw, "base_field_replica")
        old = chosen.get(row["station_id"])
        if old is None or row["received_epoch"] >= old["received_epoch"]:
            chosen[row["station_id"]] = row

    return sorted(chosen.values(), key=lambda r: (r["station_id"], -r["received_epoch"]))
