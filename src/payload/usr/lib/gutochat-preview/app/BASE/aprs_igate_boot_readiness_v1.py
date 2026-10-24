#!/usr/bin/env python3
"""Fail-closed readiness probe for GuToChat APRS receive-iGate boot activation.

Exit status contract:
  0   source DB is ready; network-disabled iGate poller may start
  1   expected source dependency not ready; defer cleanly and retry later
  255 internal/probe contract error; fail visibly

The probe opens the authoritative APRS receipt database read-only and reuses the
same source-schema contract as the proven durable outbox reader.  It never
creates or mutates the iGate outbox and contains no network transport code.
SQLite may create normal WAL/SHM sidecars in the APRS directory; C3.2R2 keeps
the main aprs.db file read-only inside the service mount namespace.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from aprs_igate_outbox_v1 import ReceiptReader

READY = 0
NOT_READY = 1
PROBE_ERROR = 255
DEFAULT_APRS_DB = Path("/var/lib/gutochat-preview/legacy-disabled/.local/share/gutochat/aprs/aprs.db")


@dataclass(frozen=True)
class ProbeResult:
    ready: bool
    db_present: bool
    db_regular_file: bool
    schema_ready: bool
    max_sequence: int | None
    reasons: tuple[str, ...]


def probe(aprs_db: Path) -> ProbeResult:
    path = Path(aprs_db).expanduser()
    reasons: list[str] = []

    try:
        st = path.stat()
    except FileNotFoundError:
        return ProbeResult(False, False, False, False, None, ("APRS_DB_NOT_PRESENT",))
    except (PermissionError, OSError) as exc:
        raise RuntimeError(f"cannot stat APRS DB {path}: {exc}") from exc

    if not stat.S_ISREG(st.st_mode):
        raise RuntimeError("APRS_DB_NOT_REGULAR_FILE")

    reader = ReceiptReader(path)
    try:
        reader.verify_schema()
        max_sequence = reader.max_sequence()
    except sqlite3.OperationalError:
        # Expected during an early boot dependency race.  A timer can retry
        # without turning this into a Restart=on-failure loop.
        reasons.append("APRS_DB_SQLITE_NOT_READY")
        return ProbeResult(False, True, True, False, None, tuple(reasons))
    except RuntimeError as exc:
        if str(exc).startswith("APRS_RECEIPT_SCHEMA_MISSING:"):
            reasons.append("APRS_RECEIPT_SCHEMA_NOT_READY")
            return ProbeResult(False, True, True, False, None, tuple(reasons))
        raise

    return ProbeResult(True, True, True, True, max_sequence, ())


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aprs-db", type=Path, default=DEFAULT_APRS_DB)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = probe(args.aprs_db)
    except Exception as exc:
        print(
            f"IGATE_BOOT_READINESS=ERROR type={type(exc).__name__} detail={exc}",
            file=sys.stderr,
            flush=True,
        )
        return PROBE_ERROR

    if args.json:
        payload = asdict(result)
        payload["reasons"] = list(result.reasons)
        print(json.dumps(payload, sort_keys=True), flush=True)
    elif result.ready:
        print(
            "IGATE_BOOT_READINESS=READY "
            f"source_max_sequence={result.max_sequence} schema=READY",
            flush=True,
        )
    else:
        print(
            "IGATE_BOOT_READINESS=NOT_READY reasons=" + ",".join(result.reasons),
            flush=True,
        )

    return READY if result.ready else NOT_READY


if __name__ == "__main__":
    raise SystemExit(main())
