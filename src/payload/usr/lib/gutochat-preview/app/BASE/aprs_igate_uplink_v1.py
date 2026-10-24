#!/usr/bin/env python3
"""C4.1 isolated loopback uplink worker for the GuToChat APRS iGate outbox.

The worker intentionally has no source APRS database input.  It owns only the
separate durable outbox and a C4.1 loopback-only APRS-IS transport.
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
from typing import Callable

from aprs_igate_outbox_v1 import (
    DeliveryUnknown, IgateOutbox, TransportNotStarted, UnsafePendingProvenance,
    PublicActivationBoundaryError,
)
from aprs_igate_policy_v1_rev2 import runtime_provenance_fingerprint, runtime_provenance_matches_expected
from aprs_igate_provenance_v1 import measure_runtime_provenance
from aprs_igate_uplink_lease_v1 import WORKER_LOCK, UplinkWorkerLease
from aprs_igate_credential_v1 import (
    CredentialError,
    credential_status,
    load_systemd_credential,
)
from aprs_is_transport_v1 import (
    AprsIsAuthRejected,
    AprsIsEndpoint,
    AprsIsPreclaimError,
    AprsIsTransport,
)


UPLINK_VERSION = "gutochat.aprs.igate.uplink.c4.2.v1"


@dataclass(frozen=True)
class DispatchResult:
    outcome: str
    uplink_key: str | None = None
    detail: str = ""


@dataclass(frozen=True)
class BackoffPolicy:
    steps: tuple[float, ...] = (5.0, 10.0, 20.0, 40.0, 60.0, 120.0, 300.0)

    def delay(self, failure_index: int) -> float:
        if failure_index < 0:
            raise ValueError("INVALID_FAILURE_INDEX")
        return self.steps[min(failure_index, len(self.steps) - 1)]


class UplinkWorker:
    def __init__(
        self,
        *,
        outbox_db: str | Path,
        endpoint: AprsIsEndpoint,
        igate_call: str,
        passcode: str,
        transport_factory: Callable[..., AprsIsTransport] = AprsIsTransport,
        provenance_provider=measure_runtime_provenance,
        worker_lock_path: str | Path = WORKER_LOCK,
    ) -> None:
        self.outbox = IgateOutbox(outbox_db)
        self.endpoint = endpoint
        self.igate_call = str(igate_call).strip().upper()
        self._passcode = str(passcode)
        self._transport_factory = transport_factory
        self.provenance_provider = provenance_provider
        self.transport: AprsIsTransport | None = None
        self.connection_failures = 0
        self._worker_lease = UplinkWorkerLease(worker_lock_path)
        self._worker_lease.acquire()
        try:
            # A crash with state=sending is intentionally terminal/ambiguous.
            self.recovered_interrupted_sends = self.outbox.recover_interrupted_sends(now=utcnow())
        except Exception:
            self._worker_lease.close()
            raise

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()
        self.transport = None
        self._worker_lease.close()

    def ensure_verified(self) -> None:
        if self.transport is not None and self.transport.verified:
            return
        self.close()
        candidate = self._transport_factory(
            endpoint=self.endpoint,
            call=self.igate_call,
            passcode=self._passcode,
        )
        try:
            candidate.connect_and_verify()
        except Exception:
            candidate.close()
            raise
        self.transport = candidate
        self.connection_failures = 0

    def dispatch_once(self, *, now: datetime) -> DispatchResult:
        """Fail provenance/queue safety first, then authenticate and claim one row."""
        provenance = self.provenance_provider()
        if not runtime_provenance_matches_expected(provenance):
            return DispatchResult("runtime_provenance_mismatch_preconnect", None, "RUNTIME_PROVENANCE_MISMATCH")
        fingerprint = runtime_provenance_fingerprint(provenance)
        pending = self.outbox.pending_provenance_counts(expected_runtime_provenance_sha256=fingerprint)
        if not pending.get("schema_ready") or pending["unsafe"]:
            return DispatchResult("unsafe_pending_provenance_preconnect", None, "OUTBOX_PENDING_PROVENANCE_UNVERIFIED_OR_MISMATCH")
        try:
            self.outbox.public_activation_guard(expected_runtime_provenance_sha256=fingerprint)
        except PublicActivationBoundaryError:
            return DispatchResult("public_activation_boundary_not_ready_preconnect", None, "PUBLIC_ACTIVATION_BOUNDARY_NOT_READY")
        try:
            self.ensure_verified()
        except AprsIsAuthRejected as exc:
            self.connection_failures += 1
            return DispatchResult("auth_rejected_preclaim", None, str(exc))
        except AprsIsPreclaimError as exc:
            self.connection_failures += 1
            return DispatchResult("connect_failed_preclaim", None, str(exc))

        assert self.transport is not None and self.transport.verified
        try:
            self.outbox.public_activation_guard(expected_runtime_provenance_sha256=fingerprint)
            row = self.outbox.claim_next(now=now, expected_runtime_provenance_sha256=fingerprint)
        except PublicActivationBoundaryError:
            return DispatchResult("public_activation_boundary_not_ready_preclaim", None, "PUBLIC_ACTIVATION_BOUNDARY_NOT_READY")
        except UnsafePendingProvenance:
            return DispatchResult("unsafe_pending_provenance_preclaim", None, "OUTBOX_PENDING_PROVENANCE_UNVERIFIED_OR_MISMATCH")
        if row is None:
            self.transport.poll_inbound(max_lines=100)
            return DispatchResult("empty", None, "")

        key = str(row["uplink_key"])
        wire = bytes(row["proposed_wire"])
        try:
            self.transport.send(wire, uplink_key=key)
        except TransportNotStarted as exc:
            self.outbox.requeue_proven_not_started(key, error=str(exc))
            return DispatchResult("requeued_not_started", key, str(exc))
        except DeliveryUnknown as exc:
            self.outbox.mark_delivery_unknown(key, now=now, error=str(exc))
            self.close()
            return DispatchResult("delivery_unknown", key, str(exc))
        except Exception as exc:
            self.outbox.mark_delivery_unknown(
                key,
                now=now,
                error=f"UNCLASSIFIED:{type(exc).__name__}:{exc}",
            )
            self.close()
            return DispatchResult("delivery_unknown", key, "UNCLASSIFIED")

        self.outbox.mark_sent(key, now=now)
        return DispatchResult("sent", key, "SUBMITTED_TO_VERIFIED_TCP_CONNECTION")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def self_check() -> dict[str, object]:
    return {
        "uplink_version": UPLINK_VERSION,
        "source_aprs_db_access": False,
        "external_network_allowed": False,
        "loopback_only": True,
        "credential_in_argv": False,
        "claim_before_verified_login": False,
        "max_claims_per_cycle": 1,
        "startup_sending_recovery": "delivery_unknown",
        "live_aprs_is_authorized": False,
    }


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="GuToChat C4.2 credential-safe isolated APRS-IS uplink worker")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("self-check")

    cred = sub.add_parser("credential-check")
    cred.add_argument("--credential-name", default="aprs-is-passcode")

    run = sub.add_parser("run-isolated-credentialed")
    run.add_argument("--outbox-db", required=True)
    run.add_argument("--host", required=True, help="must be 127.0.0.1 or ::1 literal")
    run.add_argument("--port", type=int, required=True)
    run.add_argument("--igate-call", required=True)
    run.add_argument("--credential-name", default="aprs-is-passcode")
    run.add_argument("--max-cycles", type=int, default=1)
    run.add_argument("--cycle-seconds", type=float, default=1.0)
    run.add_argument("--ack-c42-isolated-loopback-only", action="store_true")
    return p

def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "self-check":
        data = self_check()
        data.update({"credential_source": "systemd_CREDENTIALS_DIRECTORY", "credential_in_argv": False})
        print(json.dumps(data, sort_keys=True, separators=(",", ":")))
        return 0

    if args.command == "credential-check":
        print("IGATE_C42_CREDENTIAL=" + json.dumps(credential_status(args.credential_name), sort_keys=True, separators=(",", ":")))
        return 0 if credential_status(args.credential_name)["available"] else 3

    if not args.ack_c42_isolated_loopback_only:
        raise SystemExit("C42_ISOLATED_LOOPBACK_ACK_REQUIRED")
    if args.max_cycles <= 0 or args.max_cycles > 10000:
        raise SystemExit("INVALID_MAX_CYCLES")
    if args.cycle_seconds <= 0 or args.cycle_seconds > 3600:
        raise SystemExit("INVALID_CYCLE_SECONDS")

    endpoint = AprsIsEndpoint(args.host, args.port)  # hard-rejects external hosts
    try:
        runtime_passcode = load_systemd_credential(args.credential_name)
    except CredentialError as exc:
        print(f"IGATE_C42_CREDENTIAL_ERROR={exc}", flush=True)
        return 3
    worker = UplinkWorker(
        outbox_db=args.outbox_db,
        endpoint=endpoint,
        igate_call=args.igate_call,
        passcode=runtime_passcode,
    )

    stop = False
    def request_stop(signum, frame):
        del signum, frame
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    try:
        for _ in range(args.max_cycles):
            if stop:
                break
            result = worker.dispatch_once(now=utcnow())
            # detail contains only fixed error/status labels; passcode is never emitted.
            print("IGATE_C41_DISPATCH=" + json.dumps(asdict(result), sort_keys=True, separators=(",", ":")), flush=True)
            if result.outcome in {"connect_failed_preclaim", "auth_rejected_preclaim"}:
                delay = BackoffPolicy().delay(max(0, worker.connection_failures - 1))
                print(f"IGATE_C41_BACKOFF_SECONDS={delay:g}", flush=True)
                if _ + 1 < args.max_cycles:
                    time.sleep(min(delay, args.cycle_seconds))
            elif _ + 1 < args.max_cycles:
                time.sleep(args.cycle_seconds)
    finally:
        worker.close()
    print("IGATE_C41_STOPPED=TRUE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
