#!/usr/bin/env python3
"""Durable, network-free receive-iGate outbox core for GuToChat.

C3.0 deliberately contains no APRS-IS socket/login implementation.  It reads
A1H's APRS database read-only, applies the pinned iGate policy, and records
eligible work in a separate SQLite outbox owned by the future iGate component.

Safety invariants:
* aprs.db is opened read-only and PRAGMA query_only is enabled.
* initial startup watermark skips every receipt already present at first init.
* cursor and decisions are durable/idempotent in the separate outbox DB.
* a claimed row enters ``sending`` before a transport is invoked.
* any interrupted/ambiguous send becomes ``delivery_unknown`` and is never
  automatically retried.
* only an explicitly proven ``not_started`` transport result may requeue.
* no socket/connect/sendall/APRS-IS login code exists in this module.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Mapping, Protocol

from aprs_igate_policy_v1_rev2 import (
    POLICY_VERSION,
    PolicyDecision,
    RuntimeProvenance,
    evaluate_receipt,
    runtime_provenance_fingerprint,
)


OUTBOX_SCHEMA_VERSION = "gutchat.aprs.igate.outbox.v3"
ENGINE_VERSION = "gutchat.aprs.igate.engine.v3"
SOURCE_RECEIPT_TABLE = "aprs_receipts"

OUTBOX_STATES = frozenset({"queued", "sending", "sent", "delivery_unknown"})
DECISION_RESULTS = frozenset({"eligible", "rejected"})

REQUIRED_SOURCE_COLUMNS = frozenset({
    "sequence", "receipt_key", "event_schema", "network", "direction",
    "receiver_id", "received_at", "received_epoch", "raw_tnc2",
    "raw_tnc2_hash", "event_json", "event_hash", "processing_state",
    "observation_key", "domain_store_result", "last_error_code",
})


class TransportNotStarted(RuntimeError):
    """Transport proves no payload bytes were handed to the network."""


class DeliveryUnknown(RuntimeError):
    """Transport cannot prove whether the payload was delivered."""


class UnsafePendingProvenance(RuntimeError):
    """Queued work exists that is not proven against the current runtime."""


class PublicActivationBoundaryError(RuntimeError):
    """Public APRS-IS activation boundary is absent, stale, or unsafe."""


class Transport(Protocol):
    def send(self, wire: bytes, *, uplink_key: str) -> None:
        """Send exactly one already-approved APRS-IS wire payload."""


@dataclass(frozen=True)
class ScanSummary:
    start_sequence: int
    end_sequence: int
    scanned: int
    eligible: int
    rejected: int
    enqueued: int
    blocked_pending_sequence: int | None = None


@dataclass(frozen=True)
class DispatchSummary:
    outcome: str
    uplink_key: str | None = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return dt.astimezone(timezone.utc).isoformat()


def _connect_ro(path: Path) -> sqlite3.Connection:
    resolved = Path(path).expanduser().resolve()
    con = sqlite3.connect(
        f"file:{resolved}?mode=ro",
        uri=True,
        timeout=30,
    )
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    return con


def _connect_outbox(path: Path) -> sqlite3.Connection:
    resolved = Path(path).expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(resolved), timeout=30)
    os.chmod(resolved, 0o600)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=FULL")
    return con


def _rowdict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


class IgateOutbox:
    """Durable outbox/cursor store, physically separate from aprs.db."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self._process_wal_anchor: sqlite3.Connection | None = None

    def open_process_wal_anchor(self) -> bool:
        """Keep one WAL connection open for this process lifetime.

        The production poller normally uses short-lived SQLite connections.
        With a concurrent privileged read-only status reader, repeated last-
        connection close/open transitions can race WAL/SHM sidecar lifecycle
        and make a writer open fail with ``unable to open database file``.

        Holding one idle WAL connection keeps SQLite's WAL shared-memory
        lifecycle stable without holding a transaction or changing claim/send
        semantics.  Returns True only when this call opened the anchor.
        """
        if self._process_wal_anchor is not None:
            return False
        con = _connect_outbox(self.path)
        try:
            mode = str(con.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            if mode != "wal":
                raise RuntimeError("OUTBOX_WAL_ANCHOR_NOT_WAL")
            # Force a harmless schema read so the connection has fully joined
            # the WAL shared-memory state before the poll loop begins.
            con.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
        except Exception:
            con.close()
            raise
        self._process_wal_anchor = con
        return True

    def close_process_wal_anchor(self) -> bool:
        """Close the lifetime WAL anchor; returns True only if one was open."""
        con = self._process_wal_anchor
        if con is None:
            return False
        self._process_wal_anchor = None
        con.close()
        return True

    def process_wal_anchor_open(self) -> bool:
        return self._process_wal_anchor is not None

    def initialize(self, *, initial_watermark_sequence: int, now: datetime) -> bool:
        """Create schema; return True only on first initialization.

        The initial watermark is immutable after creation.  This is the core
        anti-backfill boundary: all source receipts at/below it are historical.
        """
        if initial_watermark_sequence < 0:
            raise ValueError("initial_watermark_sequence must be >= 0")
        stamp = _iso(now)
        with closing(_connect_outbox(self.path)) as con, con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS igate_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS igate_decisions (
                    source_sequence INTEGER PRIMARY KEY,
                    receipt_key TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    evaluated_epoch REAL,
                    result TEXT NOT NULL CHECK(result IN ('eligible','rejected')),
                    reason TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    runtime_provenance_sha256 TEXT,
                    uplink_key TEXT,
                    third_party_stripped INTEGER NOT NULL DEFAULT 0
                        CHECK(third_party_stripped IN (0,1))
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_igate_decisions_receipt
                    ON igate_decisions(receipt_key);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_igate_decisions_uplink
                    ON igate_decisions(uplink_key)
                    WHERE uplink_key IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_igate_decisions_retention_epoch
                    ON igate_decisions(evaluated_epoch, source_sequence);

                CREATE TABLE IF NOT EXISTS igate_outbox (
                    uplink_key TEXT PRIMARY KEY,
                    source_sequence INTEGER NOT NULL UNIQUE,
                    receipt_key TEXT NOT NULL UNIQUE,
                    proposed_tnc2 TEXT NOT NULL,
                    proposed_wire BLOB NOT NULL,
                    state TEXT NOT NULL
                        CHECK(state IN ('queued','sending','sent','delivery_unknown')),
                    queued_at TEXT NOT NULL,
                    claim_count INTEGER NOT NULL DEFAULT 0,
                    sending_started_at TEXT,
                    sent_at TEXT,
                    delivery_unknown_at TEXT,
                    last_error TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(source_sequence)
                        REFERENCES igate_decisions(source_sequence)
                );

                CREATE INDEX IF NOT EXISTS idx_igate_outbox_state_sequence
                    ON igate_outbox(state, source_sequence);

                CREATE TABLE IF NOT EXISTS igate_activation_boundaries (
                    boundary_id TEXT PRIMARY KEY,
                    prepared_at TEXT NOT NULL,
                    source_max_sequence INTEGER NOT NULL,
                    cursor_sequence INTEGER NOT NULL,
                    runtime_provenance_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK(status IN ('prepared','activated','rolled_back')),
                    finalized_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_igate_activation_boundary_status
                    ON igate_activation_boundaries(status, prepared_at);

                CREATE TABLE IF NOT EXISTS igate_dispositions (
                    source_sequence INTEGER PRIMARY KEY,
                    boundary_id TEXT NOT NULL,
                    disposition TEXT NOT NULL
                        CHECK(disposition='preactivation_backlog'),
                    disposition_at TEXT NOT NULL,
                    disposition_epoch REAL,
                    original_state TEXT NOT NULL,
                    FOREIGN KEY(source_sequence)
                        REFERENCES igate_decisions(source_sequence),
                    FOREIGN KEY(boundary_id)
                        REFERENCES igate_activation_boundaries(boundary_id)
                );

                CREATE INDEX IF NOT EXISTS idx_igate_dispositions_boundary
                    ON igate_dispositions(boundary_id, source_sequence);
                CREATE INDEX IF NOT EXISTS idx_igate_dispositions_retention_epoch
                    ON igate_dispositions(disposition_epoch, source_sequence);
                """
            )
            meta = dict(con.execute("SELECT key,value FROM igate_meta").fetchall())
            if not meta:
                entries = {
                    "schema_version": OUTBOX_SCHEMA_VERSION,
                    "engine_version": ENGINE_VERSION,
                    "initialized_at": stamp,
                    "initial_watermark_sequence": str(initial_watermark_sequence),
                    "cursor_sequence": str(initial_watermark_sequence),
                }
                con.executemany(
                    "INSERT INTO igate_meta(key,value) VALUES (?,?)",
                    entries.items(),
                )
                return True

            # Additive v1 -> v2 migration. Existing decisions intentionally get
            # NULL runtime_provenance_sha256 and are therefore never eligible
            # for blind future dispatch. A later, explicitly authorized queue
            # disposition gate must resolve any non-final legacy rows.
            decision_cols = {
                str(row[1]) for row in con.execute("PRAGMA table_info(igate_decisions)")
            }
            if "runtime_provenance_sha256" not in decision_cols:
                con.execute(
                    "ALTER TABLE igate_decisions ADD COLUMN runtime_provenance_sha256 TEXT"
                )

            schema_version = meta.get("schema_version")
            engine_version = meta.get("engine_version")
            known_migrations = {
                ("gutchat.aprs.igate.outbox.v1", "gutchat.aprs.igate.engine.v1"),
                ("gutchat.aprs.igate.outbox.v2", "gutchat.aprs.igate.engine.v2"),
            }
            if (schema_version, engine_version) in known_migrations:
                con.execute(
                    "UPDATE igate_meta SET value=? WHERE key='schema_version'",
                    (OUTBOX_SCHEMA_VERSION,),
                )
                con.execute(
                    "UPDATE igate_meta SET value=? WHERE key='engine_version'",
                    (ENGINE_VERSION,),
                )
                return False
            if schema_version != OUTBOX_SCHEMA_VERSION:
                raise RuntimeError("OUTBOX_SCHEMA_VERSION_MISMATCH")
            if engine_version != ENGINE_VERSION:
                raise RuntimeError("OUTBOX_ENGINE_VERSION_MISMATCH")
            return False

    def meta(self) -> dict[str, str]:
        with closing(_connect_outbox(self.path)) as con, con:
            return dict(con.execute("SELECT key,value FROM igate_meta").fetchall())

    def cursor_sequence(self) -> int:
        meta = self.meta()
        return int(meta["cursor_sequence"])

    def initial_watermark_sequence(self) -> int:
        meta = self.meta()
        return int(meta["initial_watermark_sequence"])

    def recover_interrupted_sends(self, *, now: datetime) -> int:
        """Make every crash-interrupted send terminal/ambiguous, never queued."""
        stamp = _iso(now)
        with closing(_connect_outbox(self.path)) as con, con:
            cur = con.execute(
                """
                UPDATE igate_outbox
                   SET state='delivery_unknown',
                       delivery_unknown_at=?,
                       last_error='INTERRUPTED_WHILE_SENDING'
                 WHERE state='sending'
                """,
                (stamp,),
            )
            return int(cur.rowcount)

    def record_decision_and_advance(
        self,
        *,
        source_sequence: int,
        receipt_key: str,
        decision: PolicyDecision,
        evaluated_at: datetime,
        runtime_provenance_sha256: str,
    ) -> bool:
        """Atomically persist one decision/enqueue and advance source cursor.

        Returns True only when a new outbox row was inserted.
        """
        if source_sequence <= 0:
            raise ValueError("source_sequence must be positive")
        stamp = _iso(evaluated_at)
        evaluated_epoch = evaluated_at.timestamp()
        result = "eligible" if decision.eligible else "rejected"
        if result not in DECISION_RESULTS:
            raise AssertionError(result)
        runtime_provenance_sha256 = str(runtime_provenance_sha256)
        if len(runtime_provenance_sha256) != 64 or any(c not in "0123456789abcdef" for c in runtime_provenance_sha256):
            raise ValueError("INVALID_RUNTIME_PROVENANCE_SHA256")
        with closing(_connect_outbox(self.path)) as con, con:
            con.execute("BEGIN IMMEDIATE")
            meta_row = con.execute(
                "SELECT value FROM igate_meta WHERE key='cursor_sequence'"
            ).fetchone()
            if meta_row is None:
                raise RuntimeError("OUTBOX_NOT_INITIALIZED")
            cursor = int(meta_row[0])

            existing = con.execute(
                "SELECT * FROM igate_decisions WHERE source_sequence=?",
                (source_sequence,),
            ).fetchone()
            inserted = False
            if existing is None:
                con.execute(
                    """
                    INSERT INTO igate_decisions(
                        source_sequence,receipt_key,evaluated_at,evaluated_epoch,result,reason,
                        policy_version,runtime_provenance_sha256,uplink_key,third_party_stripped
                    ) VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        source_sequence,
                        receipt_key,
                        stamp,
                        evaluated_epoch,
                        result,
                        decision.reason,
                        POLICY_VERSION,
                        runtime_provenance_sha256,
                        decision.uplink_key,
                        1 if decision.third_party_stripped else 0,
                    ),
                )
                if decision.eligible:
                    if (
                        decision.uplink_key is None
                        or decision.proposed_tnc2 is None
                        or decision.proposed_wire is None
                    ):
                        raise RuntimeError("ELIGIBLE_DECISION_INCOMPLETE")
                    cur = con.execute(
                        """
                        INSERT OR IGNORE INTO igate_outbox(
                            uplink_key,source_sequence,receipt_key,
                            proposed_tnc2,proposed_wire,state,queued_at
                        ) VALUES (?,?,?,?,?,'queued',?)
                        """,
                        (
                            decision.uplink_key,
                            source_sequence,
                            receipt_key,
                            decision.proposed_tnc2,
                            sqlite3.Binary(decision.proposed_wire),
                            stamp,
                        ),
                    )
                    inserted = cur.rowcount == 1
            else:
                if existing["receipt_key"] != receipt_key:
                    raise RuntimeError("SOURCE_SEQUENCE_IDENTITY_CONFLICT")

            if source_sequence > cursor:
                con.execute(
                    "UPDATE igate_meta SET value=? WHERE key='cursor_sequence'",
                    (str(source_sequence),),
                )
            return inserted

    def prepare_activation_boundary(
        self,
        *,
        boundary_id: str,
        source_max_sequence: int,
        expected_cursor_sequence: int,
        runtime_provenance_sha256: str,
        now: datetime,
    ) -> dict[str, Any]:
        """Atomically disposition all queued backlog at/below an activation boundary.

        The rows remain physically queued for audit/history, but every public
        claim path excludes rows recorded in ``igate_dispositions``.  This
        makes OFF->ON semantics "from this boundary forward" without deleting,
        marking sent, or rewriting historical policy decisions.
        """
        boundary_id = str(boundary_id).strip()
        if not boundary_id or len(boundary_id) > 128:
            raise ValueError("INVALID_ACTIVATION_BOUNDARY_ID")
        if source_max_sequence < 0 or expected_cursor_sequence < 0:
            raise ValueError("INVALID_ACTIVATION_BOUNDARY_SEQUENCE")
        fingerprint = str(runtime_provenance_sha256)
        if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
            raise ValueError("INVALID_RUNTIME_PROVENANCE_SHA256")
        stamp = _iso(now)
        disposition_epoch = now.timestamp()
        with closing(_connect_outbox(self.path)) as con, con:
            con.execute("BEGIN IMMEDIATE")
            meta = dict(con.execute("SELECT key,value FROM igate_meta").fetchall())
            if meta.get("schema_version") != OUTBOX_SCHEMA_VERSION:
                raise PublicActivationBoundaryError("OUTBOX_ACTIVATION_SCHEMA_NOT_READY")
            if meta.get("engine_version") != ENGINE_VERSION:
                raise PublicActivationBoundaryError("OUTBOX_ACTIVATION_ENGINE_NOT_READY")
            cursor = int(meta.get("cursor_sequence", "-1"))
            if cursor != int(expected_cursor_sequence) or cursor != int(source_max_sequence):
                raise PublicActivationBoundaryError("OUTBOX_NOT_CAUGHT_UP_AT_ACTIVATION_BOUNDARY")
            ambiguous = con.execute(
                "SELECT state,COUNT(*) FROM igate_outbox WHERE state IN ('sending','delivery_unknown') GROUP BY state"
            ).fetchall()
            if ambiguous:
                raise PublicActivationBoundaryError("OUTBOX_AMBIGUOUS_DELIVERY_STATE_PRESENT")

            existing = con.execute(
                "SELECT * FROM igate_activation_boundaries WHERE boundary_id=?",
                (boundary_id,),
            ).fetchone()
            if existing is None:
                con.execute(
                    """INSERT INTO igate_activation_boundaries(
                           boundary_id,prepared_at,source_max_sequence,cursor_sequence,
                           runtime_provenance_sha256,status,finalized_at
                       ) VALUES (?,?,?,?,?,'prepared',NULL)""",
                    (boundary_id, stamp, source_max_sequence, cursor, fingerprint),
                )
            else:
                if (
                    int(existing["source_max_sequence"]) != source_max_sequence
                    or int(existing["cursor_sequence"]) != cursor
                    or str(existing["runtime_provenance_sha256"]) != fingerprint
                ):
                    raise PublicActivationBoundaryError("ACTIVATION_BOUNDARY_IDENTITY_CONFLICT")

            before = int(con.execute(
                "SELECT COUNT(*) FROM igate_dispositions WHERE boundary_id=?",
                (boundary_id,),
            ).fetchone()[0])
            con.execute(
                """INSERT OR IGNORE INTO igate_dispositions(
                       source_sequence,boundary_id,disposition,disposition_at,disposition_epoch,original_state
                   )
                   SELECT o.source_sequence,?,'preactivation_backlog',?,?,o.state
                     FROM igate_outbox o
                    WHERE o.state='queued'
                      AND o.source_sequence<=?""",
                (boundary_id, stamp, disposition_epoch, source_max_sequence),
            )
            after = int(con.execute(
                "SELECT COUNT(*) FROM igate_dispositions WHERE boundary_id=?",
                (boundary_id,),
            ).fetchone()[0])
            undisposed = int(con.execute(
                """SELECT COUNT(*) FROM igate_outbox o
                    WHERE o.state='queued' AND o.source_sequence<=?
                      AND NOT EXISTS (
                          SELECT 1 FROM igate_dispositions x
                           WHERE x.source_sequence=o.source_sequence
                      )""",
                (source_max_sequence,),
            ).fetchone()[0])
            if undisposed:
                raise PublicActivationBoundaryError("PREACTIVATION_BACKLOG_DISPOSITION_INCOMPLETE")
            return {
                "boundary_id": boundary_id,
                "source_max_sequence": source_max_sequence,
                "cursor_sequence": cursor,
                "runtime_provenance_sha256": fingerprint,
                "new_dispositions": after - before,
                "boundary_dispositions": after,
                "undisposed_at_or_below_boundary": undisposed,
            }

    def finalize_activation_boundary(
        self,
        boundary_id: str,
        *,
        status: str,
        now: datetime,
    ) -> None:
        if status not in {"activated", "rolled_back"}:
            raise ValueError("INVALID_ACTIVATION_BOUNDARY_FINAL_STATUS")
        stamp = _iso(now)
        with closing(_connect_outbox(self.path)) as con, con:
            cur = con.execute(
                """UPDATE igate_activation_boundaries
                      SET status=?, finalized_at=?
                    WHERE boundary_id=? AND status IN ('prepared','activated','rolled_back')""",
                (status, stamp, str(boundary_id)),
            )
            if cur.rowcount != 1:
                raise PublicActivationBoundaryError("ACTIVATION_BOUNDARY_NOT_FOUND")

    def public_activation_guard(self, *, expected_runtime_provenance_sha256: str) -> dict[str, Any]:
        """Fail closed before public connect unless an activated boundary is valid."""
        expected = str(expected_runtime_provenance_sha256)
        with closing(_connect_outbox(self.path)) as con:
            meta = dict(con.execute("SELECT key,value FROM igate_meta").fetchall())
            if meta.get("schema_version") != OUTBOX_SCHEMA_VERSION or meta.get("engine_version") != ENGINE_VERSION:
                raise PublicActivationBoundaryError("PUBLIC_ACTIVATION_SCHEMA_NOT_READY")
            boundary = con.execute(
                """SELECT * FROM igate_activation_boundaries
                    WHERE status='activated'
                    ORDER BY prepared_at DESC, boundary_id DESC
                    LIMIT 1"""
            ).fetchone()
            if boundary is None:
                raise PublicActivationBoundaryError("PUBLIC_ACTIVATION_BOUNDARY_ABSENT")
            if str(boundary["runtime_provenance_sha256"]) != expected:
                raise PublicActivationBoundaryError("PUBLIC_ACTIVATION_PROVENANCE_MISMATCH")
            boundary_seq = int(boundary["source_max_sequence"])
            undisposed = int(con.execute(
                """SELECT COUNT(*) FROM igate_outbox o
                    WHERE o.state='queued' AND o.source_sequence<=?
                      AND NOT EXISTS (
                          SELECT 1 FROM igate_dispositions x
                           WHERE x.source_sequence=o.source_sequence
                      )""",
                (boundary_seq,),
            ).fetchone()[0])
            if undisposed:
                raise PublicActivationBoundaryError("PUBLIC_ACTIVATION_BACKLOG_UNDISPOSED")
            ambiguous = int(con.execute(
                "SELECT COUNT(*) FROM igate_outbox WHERE state IN ('sending','delivery_unknown')"
            ).fetchone()[0])
            if ambiguous:
                raise PublicActivationBoundaryError("PUBLIC_ACTIVATION_AMBIGUOUS_DELIVERY_STATE")
            return {
                "boundary_id": str(boundary["boundary_id"]),
                "source_max_sequence": boundary_seq,
                "runtime_provenance_sha256": expected,
                "status": "activated",
            }

    def disposition_counts(self) -> dict[str, int]:
        with closing(_connect_outbox(self.path)) as con:
            total = int(con.execute("SELECT COUNT(*) FROM igate_dispositions").fetchone()[0])
            queued_disposed = int(con.execute(
                """SELECT COUNT(*) FROM igate_outbox o
                    JOIN igate_dispositions x ON x.source_sequence=o.source_sequence
                   WHERE o.state='queued'"""
            ).fetchone()[0])
            queued_undisposed = int(con.execute(
                """SELECT COUNT(*) FROM igate_outbox o
                   WHERE o.state='queued' AND NOT EXISTS (
                       SELECT 1 FROM igate_dispositions x WHERE x.source_sequence=o.source_sequence
                   )"""
            ).fetchone()[0])
            return {
                "total": total,
                "queued_disposed": queued_disposed,
                "queued_undisposed": queued_undisposed,
            }

    def pending_provenance_counts(self, *, expected_runtime_provenance_sha256: str) -> dict[str, Any]:
        expected = str(expected_runtime_provenance_sha256)
        with closing(_connect_outbox(self.path)) as con:
            meta = dict(con.execute("SELECT key,value FROM igate_meta").fetchall())
            decision_cols = {str(row[1]) for row in con.execute("PRAGMA table_info(igate_decisions)")}
            queued = int(con.execute("SELECT COUNT(*) FROM igate_outbox WHERE state='queued'").fetchone()[0])
            disposed = int(con.execute(
                """SELECT COUNT(*) FROM igate_outbox o
                    JOIN igate_dispositions x ON x.source_sequence=o.source_sequence
                   WHERE o.state='queued'"""
            ).fetchone()[0])
            claimable = queued - disposed
            schema_ready = (
                meta.get("schema_version") == OUTBOX_SCHEMA_VERSION
                and meta.get("engine_version") == ENGINE_VERSION
                and "runtime_provenance_sha256" in decision_cols
            )
            if not schema_ready:
                return {
                    "schema_ready": False, "queued": queued, "disposed": disposed,
                    "claimable": claimable, "safe": 0, "unsafe": claimable,
                }
            safe = int(con.execute(
                """SELECT COUNT(*) FROM igate_outbox o
                   JOIN igate_decisions d ON d.source_sequence=o.source_sequence
                  WHERE o.state='queued' AND d.runtime_provenance_sha256=?
                    AND NOT EXISTS (
                        SELECT 1 FROM igate_dispositions x
                         WHERE x.source_sequence=o.source_sequence
                    )""",
                (expected,),
            ).fetchone()[0])
            return {
                "schema_ready": True, "queued": queued, "disposed": disposed,
                "claimable": claimable, "safe": safe, "unsafe": claimable - safe,
            }

    def claim_next(self, *, now: datetime, expected_runtime_provenance_sha256: str) -> dict[str, Any] | None:
        stamp = _iso(now)
        expected = str(expected_runtime_provenance_sha256)
        if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            raise ValueError("INVALID_EXPECTED_RUNTIME_PROVENANCE_SHA256")
        with closing(_connect_outbox(self.path)) as con, con:
            con.execute("BEGIN IMMEDIATE")
            meta = dict(con.execute("SELECT key,value FROM igate_meta").fetchall())
            decision_cols = {str(r[1]) for r in con.execute("PRAGMA table_info(igate_decisions)")}
            if (
                meta.get("schema_version") != OUTBOX_SCHEMA_VERSION
                or meta.get("engine_version") != ENGINE_VERSION
                or "runtime_provenance_sha256" not in decision_cols
            ):
                raise UnsafePendingProvenance("OUTBOX_PROVENANCE_SCHEMA_NOT_READY")
            unsafe = con.execute(
                """SELECT o.source_sequence
                     FROM igate_outbox o
                     JOIN igate_decisions d ON d.source_sequence=o.source_sequence
                    WHERE o.state='queued'
                      AND (d.runtime_provenance_sha256 IS NULL OR d.runtime_provenance_sha256<>?)
                      AND NOT EXISTS (
                          SELECT 1 FROM igate_dispositions x
                           WHERE x.source_sequence=o.source_sequence
                      )
                    ORDER BY o.source_sequence
                    LIMIT 1""",
                (expected,),
            ).fetchone()
            if unsafe is not None:
                raise UnsafePendingProvenance(
                    "OUTBOX_PENDING_PROVENANCE_UNVERIFIED_OR_MISMATCH"
                )
            row = con.execute(
                """
                SELECT o.*, d.runtime_provenance_sha256 AS runtime_provenance_sha256
                  FROM igate_outbox o
                  JOIN igate_decisions d ON d.source_sequence=o.source_sequence
                 WHERE o.state='queued' AND d.runtime_provenance_sha256=?
                   AND NOT EXISTS (
                       SELECT 1 FROM igate_dispositions x
                        WHERE x.source_sequence=o.source_sequence
                   )
                 ORDER BY o.source_sequence
                 LIMIT 1
                """,
                (expected,),
            ).fetchone()
            if row is None:
                return None
            cur = con.execute(
                """
                UPDATE igate_outbox
                   SET state='sending',
                       claim_count=claim_count+1,
                       sending_started_at=?,
                       last_error=''
                 WHERE uplink_key=? AND state='queued'
                """,
                (stamp, row["uplink_key"]),
            )
            if cur.rowcount != 1:
                raise RuntimeError("OUTBOX_CLAIM_RACE")
            claimed = con.execute(
                """
                SELECT o.*, d.runtime_provenance_sha256 AS runtime_provenance_sha256
                  FROM igate_outbox o
                  JOIN igate_decisions d ON d.source_sequence=o.source_sequence
                 WHERE o.uplink_key=?
                """,
                (row["uplink_key"],),
            ).fetchone()
            assert claimed is not None
            return _rowdict(claimed)

    def mark_sent(self, uplink_key: str, *, now: datetime) -> None:
        stamp = _iso(now)
        with closing(_connect_outbox(self.path)) as con, con:
            cur = con.execute(
                """
                UPDATE igate_outbox
                   SET state='sent', sent_at=?, last_error=''
                 WHERE uplink_key=? AND state='sending'
                """,
                (stamp, uplink_key),
            )
            if cur.rowcount != 1:
                raise RuntimeError("INVALID_SENT_TRANSITION")

    def mark_delivery_unknown(self, uplink_key: str, *, now: datetime, error: str) -> None:
        stamp = _iso(now)
        message = str(error or "DELIVERY_UNKNOWN")[:300]
        with closing(_connect_outbox(self.path)) as con, con:
            cur = con.execute(
                """
                UPDATE igate_outbox
                   SET state='delivery_unknown', delivery_unknown_at=?, last_error=?
                 WHERE uplink_key=? AND state='sending'
                """,
                (stamp, message, uplink_key),
            )
            if cur.rowcount != 1:
                raise RuntimeError("INVALID_UNKNOWN_TRANSITION")

    def requeue_proven_not_started(self, uplink_key: str, *, error: str) -> None:
        message = str(error or "TRANSPORT_NOT_STARTED")[:300]
        with closing(_connect_outbox(self.path)) as con, con:
            cur = con.execute(
                """
                UPDATE igate_outbox
                   SET state='queued', sending_started_at=NULL, last_error=?
                 WHERE uplink_key=? AND state='sending'
                """,
                (message, uplink_key),
            )
            if cur.rowcount != 1:
                raise RuntimeError("INVALID_REQUEUE_TRANSITION")

    def counts(self) -> dict[str, int]:
        with closing(_connect_outbox(self.path)) as con, con:
            result = {state: 0 for state in sorted(OUTBOX_STATES)}
            for row in con.execute(
                "SELECT state,COUNT(*) AS n FROM igate_outbox GROUP BY state"
            ):
                result[row["state"]] = int(row["n"])
            return result

    def decisions(self) -> list[dict[str, Any]]:
        with closing(_connect_outbox(self.path)) as con, con:
            return [
                _rowdict(r)
                for r in con.execute(
                    "SELECT * FROM igate_decisions ORDER BY source_sequence"
                ).fetchall()
            ]

    def outbox_rows(self) -> list[dict[str, Any]]:
        with closing(_connect_outbox(self.path)) as con, con:
            return [
                _rowdict(r)
                for r in con.execute(
                    "SELECT * FROM igate_outbox ORDER BY source_sequence"
                ).fetchall()
            ]


class ReceiptReader:
    """Read A1H receipts strictly read-only."""

    def __init__(self, aprs_db: str | Path):
        self.aprs_db = Path(aprs_db).expanduser().resolve()

    def verify_schema(self) -> None:
        with closing(_connect_ro(self.aprs_db)) as con:
            cols = {
                row["name"]
                for row in con.execute(
                    f"PRAGMA table_info({SOURCE_RECEIPT_TABLE})"
                ).fetchall()
            }
            missing = REQUIRED_SOURCE_COLUMNS - cols
            if missing:
                raise RuntimeError(
                    "APRS_RECEIPT_SCHEMA_MISSING:" + ",".join(sorted(missing))
                )

    def max_sequence(self) -> int:
        with closing(_connect_ro(self.aprs_db)) as con:
            row = con.execute(
                f"SELECT COALESCE(MAX(sequence),0) FROM {SOURCE_RECEIPT_TABLE}"
            ).fetchone()
            return int(row[0])

    def rows_after(self, sequence: int, *, limit: int = 100) -> list[dict[str, Any]]:
        if sequence < 0 or limit <= 0 or limit > 1000:
            raise ValueError("invalid sequence/limit")
        with closing(_connect_ro(self.aprs_db)) as con:
            rows = con.execute(
                f"""
                SELECT sequence,receipt_key,event_schema,network,direction,
                       receiver_id,received_at,received_epoch,raw_tnc2,
                       raw_tnc2_hash,event_json,event_hash,processing_state,
                       observation_key,domain_store_result,last_error_code
                  FROM {SOURCE_RECEIPT_TABLE}
                 WHERE sequence > ?
                 ORDER BY sequence
                 LIMIT ?
                """,
                (sequence, limit),
            ).fetchall()
            return [_rowdict(row) for row in rows]


class OutboxEngine:
    """Network-free bridge from read-only receipts to a durable outbox."""

    def __init__(
        self,
        *,
        reader: ReceiptReader,
        outbox: IgateOutbox,
        igate_call: str,
        provenance: RuntimeProvenance,
    ):
        same_path = reader.aprs_db == outbox.path
        same_file = False
        if reader.aprs_db.exists() and outbox.path.exists():
            same_file = os.path.samefile(reader.aprs_db, outbox.path)
        if same_path or same_file:
            raise ValueError("OUTBOX_MUST_BE_SEPARATE_FROM_APRS_DB")
        self.reader = reader
        self.outbox = outbox
        self.igate_call = igate_call
        self.provenance = provenance

    def initialize(self, *, now: datetime) -> bool:
        self.reader.verify_schema()
        watermark = self.reader.max_sequence()
        created = self.outbox.initialize(
            initial_watermark_sequence=watermark,
            now=now,
        )
        self.outbox.recover_interrupted_sends(now=now)
        return created

    def scan_once(self, *, now: datetime, limit: int = 100) -> ScanSummary:
        start = self.outbox.cursor_sequence()
        provenance_sha256 = runtime_provenance_fingerprint(self.provenance)
        rows = self.reader.rows_after(start, limit=limit)
        eligible = rejected = enqueued = 0
        end = start
        blocked_pending_sequence: int | None = None
        for receipt in rows:
            seq = int(receipt["sequence"])
            # A1H persists a receipt as ``received`` before finalizing it.  Do
            # not turn that transient state into a permanent rejection and do
            # not advance the cursor past it: later receipts must wait behind
            # the same ordered finalization barrier.
            if receipt.get("processing_state") == "received":
                blocked_pending_sequence = seq
                break
            decision = evaluate_receipt(
                receipt,
                igate_call=self.igate_call,
                provenance=self.provenance,
                now=now,
            )
            if decision.eligible:
                eligible += 1
            else:
                rejected += 1
            if self.outbox.record_decision_and_advance(
                source_sequence=seq,
                receipt_key=str(receipt["receipt_key"]),
                decision=decision,
                evaluated_at=now,
                runtime_provenance_sha256=provenance_sha256,
            ):
                enqueued += 1
            end = seq
        return ScanSummary(
            start_sequence=start,
            end_sequence=end,
            scanned=len(rows),
            eligible=eligible,
            rejected=rejected,
            enqueued=enqueued,
            blocked_pending_sequence=blocked_pending_sequence,
        )

    def dispatch_one(self, transport: Transport, *, now: datetime) -> DispatchSummary:
        row = self.outbox.claim_next(
            now=now,
            expected_runtime_provenance_sha256=runtime_provenance_fingerprint(self.provenance),
        )
        if row is None:
            return DispatchSummary("empty", None)
        key = str(row["uplink_key"])
        wire = bytes(row["proposed_wire"])
        try:
            transport.send(wire, uplink_key=key)
        except TransportNotStarted as exc:
            self.outbox.requeue_proven_not_started(key, error=str(exc))
            return DispatchSummary("requeued_not_started", key)
        except DeliveryUnknown as exc:
            self.outbox.mark_delivery_unknown(key, now=now, error=str(exc))
            return DispatchSummary("delivery_unknown", key)
        except Exception as exc:  # safest handling for an unclassified send failure
            self.outbox.mark_delivery_unknown(
                key,
                now=now,
                error=f"UNCLASSIFIED:{type(exc).__name__}:{exc}",
            )
            return DispatchSummary("delivery_unknown", key)
        self.outbox.mark_sent(key, now=now)
        return DispatchSummary("sent", key)


class RecordingMockTransport:
    """C3.0 test sink.  Stores bytes in memory and never touches a network."""

    def __init__(self, mode: str = "success"):
        if mode not in {"success", "not_started", "unknown", "error"}:
            raise ValueError("invalid mock mode")
        self.mode = mode
        self.calls: list[tuple[str, bytes]] = []

    def send(self, wire: bytes, *, uplink_key: str) -> None:
        if self.mode == "not_started":
            raise TransportNotStarted("MOCK_PROVEN_NOT_STARTED")
        self.calls.append((uplink_key, bytes(wire)))
        if self.mode == "unknown":
            raise DeliveryUnknown("MOCK_DELIVERY_UNKNOWN")
        if self.mode == "error":
            raise RuntimeError("MOCK_UNCLASSIFIED_FAILURE")


def self_check() -> dict[str, Any]:
    """Network-free static identity summary for staging/live preflight."""
    return {
        "engine_version": ENGINE_VERSION,
        "outbox_schema_version": OUTBOX_SCHEMA_VERSION,
        "outbox_states": sorted(OUTBOX_STATES),
        "source_table": SOURCE_RECEIPT_TABLE,
        "network_implementation_present": False,
    }


if __name__ == "__main__":
    print(json.dumps(self_check(), sort_keys=True, separators=(",", ":")))
