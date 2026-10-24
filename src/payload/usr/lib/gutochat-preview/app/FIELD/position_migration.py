#!/usr/bin/env python3
"""Narrow, privacy-safe migrations for LoRa Chat position storage."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from position_store import PositionStore


def migrate_position_storage(db_path: Path) -> dict[str, Any]:
    """Remove only the exact known corrupt precision-midpoint signature.

    The operation intentionally leaves position revisions, settings and every
    unrelated table untouched. Keeping the revision cursor monotonic ensures a
    later trustworthy position receives a newer revision and synchronizes
    normally to Mobile.
    """
    store = PositionStore(Path(db_path))
    raw_before = store.raw_count()
    trusted_before = store.count()
    suspicious_before = store.suspicious_count()
    removed = store.purge_suspicious_positions()
    raw_after = store.raw_count()
    trusted_after = store.count()
    suspicious_after = store.suspicious_count()
    integrity = store.integrity_check()

    if removed != suspicious_before:
        raise RuntimeError(
            "Uoverensstemmelse under opprydding av mistenkelige posisjoner"
        )
    if suspicious_after != 0:
        raise RuntimeError("Mistenkelige posisjonsrader finnes fortsatt")
    if trusted_after != trusted_before:
        raise RuntimeError("Oppryddingen endret antallet troverdige posisjoner")
    if raw_after != raw_before - removed:
        raise RuntimeError("Oppryddingen fjernet et uventet antall posisjonsrader")
    if integrity.lower() != "ok":
        raise RuntimeError(f"SQLite quick_check feilet: {integrity}")

    return {
        "raw_before": raw_before,
        "trusted_before": trusted_before,
        "suspicious_before": suspicious_before,
        "removed_suspicious": removed,
        "raw_after": raw_after,
        "trusted_after": trusted_after,
        "suspicious_after": suspicious_after,
        "integrity": integrity,
    }
