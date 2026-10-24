"""Persist historical integrity evidence without opening the application database."""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def _identity(database: Path) -> dict:
    resolved = database.resolve(strict=True)
    stat = resolved.stat()
    return {"path": str(resolved), "device": stat.st_dev, "inode": stat.st_ino}


def _record_path(database: Path) -> Path:
    return database.with_name(database.name + ".integrity-status.json")


def load_integrity_record(database: Path) -> dict:
    """Return past evidence only for the same file, never a new integrity check."""
    fallback = {"integrity": "not_run", "completed_at": ""}
    try:
        path = _record_path(database)
        if path.is_symlink() or path.stat().st_size > 16384:
            return fallback
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("version") != 1 or record.get("database") != _identity(database):
            return fallback
        integrity, completed = record["integrity"], record["completed_at"]
        if not isinstance(integrity, str) or not integrity or len(integrity) > 8192:
            return fallback
        if integrity == "not_run" or not isinstance(completed, str):
            return fallback
        stamp = datetime.fromisoformat(completed)
        if stamp.tzinfo is None or stamp > datetime.now(timezone.utc):
            return fallback
        return {"integrity": integrity, "completed_at": completed}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return fallback


def save_integrity_record(database: Path, result: dict) -> bool:
    """Atomically save a completed result. Failure leaves previous evidence intact."""
    temporary = None
    try:
        identity = _identity(database)
        record = {"version": 1, "database": identity,
                  "integrity": result["integrity"], "completed_at": result["completed_at"]}
        if record["integrity"] == "not_run":
            return False
        path = _record_path(database)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=path.name + ".", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(record, stream)
            stream.flush()
            os.fsync(stream.fileno())
        if _identity(database) != identity:
            return False
        os.replace(temporary, path)
        temporary = None
        return True
    except (OSError, ValueError, TypeError, KeyError):
        return False
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
