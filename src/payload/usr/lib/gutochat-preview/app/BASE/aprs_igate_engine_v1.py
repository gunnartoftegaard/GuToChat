#!/usr/bin/env python3
"""Network-disabled durable receive-iGate outbox poller for GuToChat C3.2.

This component deliberately has no APRS-IS transport implementation.  It reads
A1H receipts through the C3.0 read-only ReceiptReader, applies the pinned policy,
and persists decisions/eligible work in the separate durable outbox.

The production-shaped systemd candidate runs with dispatch disabled and with
systemd network address families restricted to AF_UNIX.  Mock/null dispatch
exists only for isolated validation of the durable state machine.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import signal
import sys
import time
from typing import Any

from aprs_igate_outbox_v1 import (
    DispatchSummary,
    IgateOutbox,
    OutboxEngine,
    ReceiptReader,
    RecordingMockTransport,
    ScanSummary,
    TransportNotStarted,
)
from aprs_igate_policy_v1_rev2 import (
    RuntimeProvenance,
    runtime_provenance_matches_expected,
)
from aprs_igate_provenance_v1 import measure_runtime_provenance

ENGINE_RUNNER_VERSION = "gutchat.aprs.igate.poller.v1"
ALLOWED_DISPATCH_MODES = frozenset({
    "disabled",
    "null",
    "mock-success",
    "mock-not-started",
    "mock-unknown",
    "mock-error",
})


class NullTransport:
    """Proves that no transport was started; never records/sends payload bytes."""

    def send(self, wire: bytes, *, uplink_key: str) -> None:
        del wire, uplink_key
        raise TransportNotStarted("NULL_TRANSPORT_NETWORK_DISABLED")


@dataclass(frozen=True)
class CycleSummary:
    scan: ScanSummary
    dispatches: tuple[DispatchSummary, ...]
    outbox_counts: dict[str, int]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def runtime_provenance() -> RuntimeProvenance:
    """Measure the current local runtime identity; never synthesize it."""
    return measure_runtime_provenance()


def make_transport(mode: str):
    if mode == "disabled":
        return None
    if mode == "null":
        return NullTransport()
    mapping = {
        "mock-success": "success",
        "mock-not-started": "not_started",
        "mock-unknown": "unknown",
        "mock-error": "error",
    }
    try:
        return RecordingMockTransport(mapping[mode])
    except KeyError as exc:
        raise ValueError("INVALID_DISPATCH_MODE") from exc


class PollerRuntime:
    def __init__(
        self,
        *,
        aprs_db: str | Path,
        outbox_db: str | Path,
        igate_call: str,
        dispatch_mode: str = "disabled",
        provenance_provider=runtime_provenance,
    ):
        if dispatch_mode not in ALLOWED_DISPATCH_MODES:
            raise ValueError("INVALID_DISPATCH_MODE")
        self.reader = ReceiptReader(aprs_db)
        self.outbox = IgateOutbox(outbox_db)
        self.provenance_provider = provenance_provider
        initial_provenance = self._measure_expected_provenance()
        self.engine = OutboxEngine(
            reader=self.reader,
            outbox=self.outbox,
            igate_call=igate_call,
            provenance=initial_provenance,
        )
        self.dispatch_mode = dispatch_mode
        self.transport = make_transport(dispatch_mode)

    def _measure_expected_provenance(self) -> RuntimeProvenance:
        provenance = self.provenance_provider()
        if not runtime_provenance_matches_expected(provenance):
            raise RuntimeError("RUNTIME_PROVENANCE_MISMATCH")
        return provenance

    def initialize(self, *, now: datetime) -> bool:
        # Open the process-lifetime WAL anchor before schema/init work so there
        # is no startup window in which a concurrent privileged status reader
        # can become the only connection managing WAL/SHM sidecar lifecycle.
        self.outbox.open_process_wal_anchor()
        try:
            return self.engine.initialize(now=now)
        except Exception:
            self.outbox.close_process_wal_anchor()
            raise

    def close(self) -> None:
        self.outbox.close_process_wal_anchor()

    def cycle(
        self,
        *,
        now: datetime,
        scan_limit: int,
        dispatch_limit: int,
    ) -> CycleSummary:
        if scan_limit <= 0 or scan_limit > 1000:
            raise ValueError("INVALID_SCAN_LIMIT")
        if dispatch_limit < 0 or dispatch_limit > 1000:
            raise ValueError("INVALID_DISPATCH_LIMIT")
        if self.dispatch_mode == "disabled" and dispatch_limit != 0:
            raise ValueError("DISPATCH_DISABLED_REQUIRES_ZERO_LIMIT")
        if self.dispatch_mode != "disabled" and dispatch_limit == 0:
            raise ValueError("DISPATCH_MODE_REQUIRES_POSITIVE_LIMIT")

        # Measure on every cycle. A changed/missing runtime identity blocks the
        # scan before any cursor/decision write, so a transient mismatch cannot
        # permanently reject receipts.
        self.engine.provenance = self._measure_expected_provenance()
        scan = self.engine.scan_once(now=now, limit=scan_limit)
        dispatches: list[DispatchSummary] = []
        if self.transport is not None:
            for _ in range(dispatch_limit):
                d = self.engine.dispatch_one(self.transport, now=now)
                dispatches.append(d)
                if d.outcome == "empty":
                    break
                # Null/proven-not-started requeues the same row.  Do not spin
                # and repeatedly reclaim it within the same cycle.
                if d.outcome == "requeued_not_started":
                    break
        return CycleSummary(
            scan=scan,
            dispatches=tuple(dispatches),
            outbox_counts=self.outbox.counts(),
        )


def _summary_json(summary: CycleSummary) -> str:
    return json.dumps(
        {
            "scan": asdict(summary.scan),
            "dispatches": [asdict(d) for d in summary.dispatches],
            "outbox_counts": summary.outbox_counts,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def self_check() -> dict[str, Any]:
    return {
        "runner_version": ENGINE_RUNNER_VERSION,
        "dispatch_modes": sorted(ALLOWED_DISPATCH_MODES),
        "default_dispatch_mode": "disabled",
        "network_transport_present": False,
        "runtime_provenance_source": "measured_local_files_each_cycle",
        "runtime_provenance_fail_closed_before_scan": True,
        "outbox_wal_anchor": "process_lifetime",
    }


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="GuToChat network-disabled receive-iGate outbox poller")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("self-check")

    run = sub.add_parser("run")
    run.add_argument("--aprs-db", required=True)
    run.add_argument("--outbox-db", required=True)
    run.add_argument("--igate-call", required=True)
    run.add_argument("--poll-seconds", type=float, default=2.0)
    run.add_argument("--scan-limit", type=int, default=100)
    run.add_argument("--dispatch-mode", choices=sorted(ALLOWED_DISPATCH_MODES), default="disabled")
    run.add_argument("--dispatch-limit", type=int, default=0)
    run.add_argument("--allow-isolated-test-dispatch", action="store_true",
                     help="required for any non-disabled mock/null dispatch mode")
    run.add_argument("--max-cycles", type=int, default=0,
                     help="0 means continuous; positive values are bounded test/staging runs")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "self-check":
        print(json.dumps(self_check(), sort_keys=True, separators=(",", ":")))
        return 0

    if args.poll_seconds <= 0 or args.poll_seconds > 3600:
        raise SystemExit("INVALID_POLL_SECONDS")
    if args.max_cycles < 0:
        raise SystemExit("INVALID_MAX_CYCLES")
    if args.dispatch_mode != "disabled" and not args.allow_isolated_test_dispatch:
        raise SystemExit("NON_DISABLED_DISPATCH_REQUIRES_ISOLATED_TEST_ACK")

    runtime = PollerRuntime(
        aprs_db=args.aprs_db,
        outbox_db=args.outbox_db,
        igate_call=args.igate_call,
        dispatch_mode=args.dispatch_mode,
    )
    created = runtime.initialize(now=utcnow())
    print("IGATE_POLLER_INIT=" + ("CREATED" if created else "EXISTING"), flush=True)
    print("IGATE_POLLER_WAL_ANCHOR=OPEN", flush=True)
    print("IGATE_POLLER_NETWORK_TRANSPORT=DISABLED", flush=True)
    print("IGATE_POLLER_DISPATCH_MODE=" + args.dispatch_mode, flush=True)

    stop = False

    def request_stop(signum, frame):
        del signum, frame
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    cycles = 0
    try:
        while not stop:
            summary = runtime.cycle(
                now=utcnow(),
                scan_limit=args.scan_limit,
                dispatch_limit=args.dispatch_limit,
            )
            print("IGATE_POLLER_CYCLE=" + _summary_json(summary), flush=True)
            cycles += 1
            if args.max_cycles and cycles >= args.max_cycles:
                break
            # signal-aware enough for this network-disabled poller; service stop
            # may wait at most poll_seconds before clean exit.
            time.sleep(args.poll_seconds)
    finally:
        runtime.close()

    print("IGATE_POLLER_WAL_ANCHOR=CLOSED", flush=True)
    print("IGATE_POLLER_STOPPED=TRUE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
