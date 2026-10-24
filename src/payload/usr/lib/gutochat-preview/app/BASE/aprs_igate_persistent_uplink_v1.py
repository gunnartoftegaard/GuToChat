#!/usr/bin/env python3
"""C5.1 isolated persistent receive-iGate uplink worker candidate.

This module is designed for later persistent APRS-IS receive-iGate operation,
but C5.1 itself is isolated/mock-only validation.

Hard invariants:
- fixed APRS-IS endpoint euro.aprs2.net:14580 and login N0CALL;
- systemd credential only; no CLI configuration;
- verified login before every outbox claim;
- at most one claimed row in flight;
- arm marker checked before connect, before claim, and immediately before send;
- receive-only qAO,N0CALL wire revalidation before every payload send;
- APRS-IS inbound packet lines are discarded, never routed;
- startup residual sending rows become delivery_unknown;
- ambiguous payload send becomes delivery_unknown and is never auto-retried;
- no source APRS DB, RF/audio/serial/GPIO/PTT/CAT/KISS/AGW/Meshtastic path.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import select
import socket
import stat
import sys
import time
from typing import Callable

from aprs_igate_credential_v1 import CredentialError, load_systemd_credential
from aprs_igate_outbox_v1 import (
    DeliveryUnknown,
    IgateOutbox,
    TransportNotStarted,
    UnsafePendingProvenance,
    PublicActivationBoundaryError,
)
from aprs_igate_policy_v1_rev2 import (
    runtime_provenance_fingerprint,
    runtime_provenance_matches_expected,
)
from aprs_igate_provenance_v1 import measure_runtime_provenance
from aprs_igate_uplink_lease_v1 import WORKER_LOCK, WorkerLeaseHeld, worker_lease

PERSISTENT_VERSION = "gutochat.aprs.igate.c5.1.persistent-uplink.v1"
ENDPOINT_HOST = "euro.aprs2.net"
ENDPOINT_PORT = 14580
IGATE_CALL = "N0CALL"
CLIENT_NAME = "GuToChat"
CLIENT_VERSION = "2.5.0-beta4"
CREDENTIAL_NAME = "aprs-is-passcode"
OUTBOX_DB = "/var/lib/gutochat-aprs-igate/igate_outbox.db"
ARM_MARKER = "/etc/gutochat-aprs-igate/ALLOW_LIVE_UPLINK"
MAX_WIRE_BYTES = 512
MAX_SERVER_LINE_BYTES = 4096
MIN_SECONDS_BETWEEN_CLAIMS = 1.0
IDLE_POLL_SECONDS = 1.0
BACKOFF_SECONDS = (5.0, 10.0, 20.0, 40.0, 60.0, 120.0, 300.0)
CALL_RE = re.compile(r"^[A-Z0-9]{3,6}(?:-[A-Z0-9]{1,2})?$")
PASS_RE = re.compile(r"^[0-9]{1,5}$")
Q_RE = re.compile(r"^qA[A-Z]$", re.IGNORECASE)
LOGRESP_RE = re.compile(
    r"^#\s*logresp\s+(?P<call>\S+)\s+(?P<state>verified|unverified)\b",
    re.IGNORECASE,
)


class PersistentError(RuntimeError):
    pass


class PreclaimConnectionError(PersistentError):
    pass


class AuthenticationRejected(PersistentError):
    pass


class InvalidArmMarker(PersistentError):
    pass




@dataclass(frozen=True)
class PersistentRunSummary:
    persistent_version: str
    endpoint_host: str
    endpoint_port: int
    igate_call: str
    startup_recovered_sending: int
    cycles: int
    verified_connections: int
    reconnect_failures: int
    claims: int
    sent: int
    delivery_unknown: int
    proven_not_started_requeues: int
    inbound_packets_discarded: int
    comments_received: int
    exit_reason: str
    max_in_flight: int


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _login_line(passcode: str) -> bytes:
    if not CALL_RE.fullmatch(IGATE_CALL):
        raise PersistentError("INVALID_FIXED_IGATE_CALL")
    text = str(passcode)
    if not PASS_RE.fullmatch(text) or not (0 <= int(text, 10) <= 32767):
        raise PersistentError("INVALID_CREDENTIAL_FORMAT")
    return (
        f"user {IGATE_CALL} pass {text} vers {CLIENT_NAME} {CLIENT_VERSION}\r\n"
    ).encode("ascii")


def _parse_logresp(line: str) -> None:
    match = LOGRESP_RE.match(str(line).strip())
    if match is None:
        raise PreclaimConnectionError("LOGIN_RESPONSE_MALFORMED")
    if match.group("call").upper() != IGATE_CALL:
        raise AuthenticationRejected("LOGIN_RESPONSE_CALL_MISMATCH")
    if match.group("state").lower() != "verified":
        raise AuthenticationRejected("LOGIN_UNVERIFIED")


def _validate_live_wire(wire: bytes) -> bytes:
    if not isinstance(wire, (bytes, bytearray, memoryview)):
        raise TransportNotStarted("WIRE_MUST_BE_BYTES")
    data = bytes(wire)
    if not data.endswith(b"\r\n"):
        raise TransportNotStarted("WIRE_MISSING_CRLF")
    if len(data) > MAX_WIRE_BYTES:
        raise TransportNotStarted("WIRE_EXCEEDS_512_BYTES")
    body = data[:-2]
    if not body or b"\r" in body or b"\n" in body:
        raise TransportNotStarted("WIRE_INVALID_LINE_FRAMING")
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TransportNotStarted("WIRE_NOT_ASCII") from exc
    if ">" not in text or ":" not in text:
        raise TransportNotStarted("WIRE_NOT_TNC2")
    source, rest = text.split(">", 1)
    header, _info = rest.split(":", 1)
    route = header.split(",")
    if not source or len(route) < 3:
        raise TransportNotStarted("WIRE_ROUTE_INCOMPLETE")
    path = route[1:]
    if len(path) < 2 or path[-2].upper() != "QAO" or path[-1].upper() != IGATE_CALL:
        raise TransportNotStarted("WIRE_RECEIVE_ONLY_QAO_IGATE_MISMATCH")
    qao_count = 0
    for index, hop in enumerate(path):
        bare = hop.rstrip("*").upper()
        if bare == "QAO":
            qao_count += 1
        if index < len(path) - 2:
            if bare in {"TCPIP", "TCPXX", "NOGATE", "RFONLY", "I"}:
                raise TransportNotStarted("WIRE_FORBIDDEN_PATH_TOKEN")
            if Q_RE.fullmatch(bare):
                raise TransportNotStarted("WIRE_PREEXISTING_Q_CONSTRUCT")
    if qao_count != 1:
        raise TransportNotStarted("WIRE_QAO_COUNT_INVALID")
    return data


def arm_marker_is_valid(path: str | Path = ARM_MARKER) -> bool:
    """Return True only for a regular, root-owned, non-writable-by-others marker."""
    marker = Path(path)
    try:
        st = marker.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise InvalidArmMarker("ARM_MARKER_STAT_FAILED") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise InvalidArmMarker("ARM_MARKER_NOT_REGULAR")
    if st.st_uid != 0:
        raise InvalidArmMarker("ARM_MARKER_NOT_ROOT_OWNED")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise InvalidArmMarker("ARM_MARKER_GROUP_OR_OTHER_WRITABLE")
    return True


class PersistentSession:
    """One APRS-IS connection retained across multiple single-claim cycles."""

    def __init__(
        self,
        *,
        passcode: str,
        socket_factory: Callable[..., socket.socket] = socket.create_connection,
        connect_timeout: float = 8.0,
        login_timeout: float = 8.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._login = _login_line(passcode)
        self._socket_factory = socket_factory
        self.connect_timeout = float(connect_timeout)
        self.login_timeout = float(login_timeout)
        self._monotonic = monotonic
        self.sock: socket.socket | None = None
        self.buffer = bytearray()
        self.verified = False
        self.banner_seen = False
        self.peer_ip = "UNKNOWN"
        self.comments = 0
        self.discarded = 0

    def _recv_line(self, deadline: float) -> str:
        if self.sock is None:
            raise PreclaimConnectionError("SOCKET_NOT_CONNECTED")
        while True:
            pos = self.buffer.find(b"\n")
            if pos >= 0:
                raw = bytes(self.buffer[: pos + 1])
                del self.buffer[: pos + 1]
                if len(raw) > MAX_SERVER_LINE_BYTES:
                    raise PreclaimConnectionError("SERVER_LINE_TOO_LONG")
                return raw.rstrip(b"\r\n").decode("ascii", errors="replace")
            remain = deadline - self._monotonic()
            if remain <= 0:
                raise PreclaimConnectionError("SERVER_LINE_TIMEOUT")
            self.sock.settimeout(min(remain, 0.5))
            try:
                chunk = self.sock.recv(2048)
            except socket.timeout:
                continue
            except OSError as exc:
                raise PreclaimConnectionError("SOCKET_READ_FAILED") from exc
            if not chunk:
                raise PreclaimConnectionError("SERVER_CLOSED")
            self.buffer.extend(chunk)
            if len(self.buffer) > MAX_SERVER_LINE_BYTES:
                raise PreclaimConnectionError("SERVER_LINE_TOO_LONG")

    def connect_and_verify(self) -> None:
        if self.verified and self.sock is not None:
            return
        self.close()
        self.banner_seen = False
        try:
            self.sock = self._socket_factory(
                (ENDPOINT_HOST, ENDPOINT_PORT), timeout=self.connect_timeout
            )
        except OSError as exc:
            raise PreclaimConnectionError("CONNECT_FAILED") from exc
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                peer = self.sock.getpeername()
                self.peer_ip = str(peer[0]) if isinstance(peer, tuple) and peer else str(peer)
            except OSError:
                self.peer_ip = "UNKNOWN"

            deadline = self._monotonic() + self.login_timeout
            while not self.banner_seen:
                line = self._recv_line(deadline)
                if line.startswith("#"):
                    self.comments += 1
                    self.banner_seen = True
                else:
                    self.discarded += 1

            try:
                self.sock.sendall(self._login)
            except OSError as exc:
                raise PreclaimConnectionError("LOGIN_WRITE_FAILED") from exc

            deadline = self._monotonic() + self.login_timeout
            while not self.verified:
                line = self._recv_line(deadline)
                if line.startswith("#"):
                    self.comments += 1
                    if LOGRESP_RE.match(line.strip()):
                        _parse_logresp(line)
                        self.verified = True
                else:
                    self.discarded += 1
        except AuthenticationRejected:
            self.close()
            raise
        except Exception:
            self.close()
            raise

    def poll_inbound(self, *, max_lines: int = 100) -> int:
        """Drain ready lines; packet lines are counted/discarded only.

        A peer close is surfaced before a new claim, allowing reconnect without
        creating an ambiguous outbox row.
        """
        if max_lines <= 0 or max_lines > 1000:
            raise ValueError("INVALID_MAX_LINES")
        if self.sock is None or not self.verified:
            raise PreclaimConnectionError("SESSION_NOT_VERIFIED")
        processed = 0
        while processed < max_lines:
            pos = self.buffer.find(b"\n")
            if pos < 0:
                try:
                    ready, _, _ = select.select([self.sock], [], [], 0)
                except (OSError, ValueError) as exc:
                    raise PreclaimConnectionError("SESSION_POLL_FAILED") from exc
                if not ready:
                    break
                try:
                    chunk = self.sock.recv(2048)
                except (BlockingIOError, socket.timeout):
                    break
                except OSError as exc:
                    raise PreclaimConnectionError("SESSION_READ_FAILED") from exc
                if not chunk:
                    raise PreclaimConnectionError("SESSION_CLOSED")
                self.buffer.extend(chunk)
                if len(self.buffer) > MAX_SERVER_LINE_BYTES:
                    raise PreclaimConnectionError("SERVER_LINE_TOO_LONG")
                continue
            raw = bytes(self.buffer[: pos + 1])
            del self.buffer[: pos + 1]
            line = raw.rstrip(b"\r\n").decode("ascii", errors="replace")
            if line.startswith("#"):
                self.comments += 1
            else:
                self.discarded += 1
            processed += 1
        return processed

    def send_payload(self, wire: bytes) -> None:
        if self.sock is None or not self.verified:
            raise TransportNotStarted("SESSION_NOT_VERIFIED")
        data = _validate_live_wire(wire)
        try:
            self.sock.sendall(data)
        except OSError as exc:
            self.close()
            raise DeliveryUnknown("PAYLOAD_WRITE_AMBIGUOUS") from exc

    def close(self) -> None:
        sock, self.sock = self.sock, None
        self.verified = False
        self.buffer.clear()
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def forget_credential(self) -> None:
        self._login = b""



class PersistentWorker:
    def __init__(
        self,
        *,
        passcode: str,
        outbox_db: str = OUTBOX_DB,
        session_factory: Callable[..., PersistentSession] = PersistentSession,
        arm_checker: Callable[[], bool] = arm_marker_is_valid,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = _utcnow,
        min_seconds_between_claims: float = MIN_SECONDS_BETWEEN_CLAIMS,
        idle_poll_seconds: float = IDLE_POLL_SECONDS,
        backoff_seconds: tuple[float, ...] = BACKOFF_SECONDS,
        provenance_provider=measure_runtime_provenance,
        worker_lock_path: str | Path = WORKER_LOCK,
    ) -> None:
        if min_seconds_between_claims < 0 or idle_poll_seconds < 0:
            raise ValueError("INVALID_WORKER_INTERVAL")
        if not backoff_seconds or any(x <= 0 for x in backoff_seconds):
            raise ValueError("INVALID_BACKOFF")
        self._passcode = str(passcode)
        _login_line(self._passcode)  # validate without exposing value
        self.outbox = IgateOutbox(outbox_db)
        self.session_factory = session_factory
        self.arm_checker = arm_checker
        self.sleep = sleep
        self.now = now
        self.min_seconds_between_claims = float(min_seconds_between_claims)
        self.idle_poll_seconds = float(idle_poll_seconds)
        self.backoff_seconds = tuple(float(x) for x in backoff_seconds)
        self.provenance_provider = provenance_provider
        self.worker_lock_path = Path(worker_lock_path)

    def _runtime_fingerprint(self) -> str:
        provenance = self.provenance_provider()
        if not runtime_provenance_matches_expected(provenance):
            raise PersistentError("RUNTIME_PROVENANCE_MISMATCH")
        return runtime_provenance_fingerprint(provenance)

    def _queue_provenance_safe(self, expected_fingerprint: str) -> bool:
        counts = self.outbox.pending_provenance_counts(
            expected_runtime_provenance_sha256=expected_fingerprint
        )
        return bool(counts.get("schema_ready")) and counts["unsafe"] == 0

    def _armed(self) -> bool:
        try:
            return bool(self.arm_checker())
        except InvalidArmMarker:
            raise
        except Exception as exc:
            raise InvalidArmMarker("ARM_CHECK_FAILED") from exc

    def run(self, *, max_cycles: int | None = None, max_sends: int | None = None) -> PersistentRunSummary:
        with worker_lease(self.worker_lock_path):
            return self._run_leased(max_cycles=max_cycles, max_sends=max_sends)

    def _run_leased(self, *, max_cycles: int | None = None, max_sends: int | None = None) -> PersistentRunSummary:
        if max_cycles is not None and max_cycles <= 0:
            raise ValueError("INVALID_MAX_CYCLES")
        if max_sends is not None and max_sends <= 0:
            raise ValueError("INVALID_MAX_SENDS")

        recovered = self.outbox.recover_interrupted_sends(now=self.now())
        cycles = verified_connections = reconnect_failures = claims = sent = 0
        unknown = requeues = discarded = comments = 0
        max_in_flight = 0
        backoff_index = 0
        session: PersistentSession | None = None
        exit_reason = "stopped"

        try:
            while True:
                if max_cycles is not None and cycles >= max_cycles:
                    exit_reason = "max_cycles"
                    break
                if max_sends is not None and sent >= max_sends:
                    exit_reason = "max_sends"
                    break
                if not self._armed():
                    exit_reason = "unarmed"
                    break

                # Fail before any public connect when runtime identity or pending
                # queue provenance is not exactly the current production contract.
                expected_fingerprint = self._runtime_fingerprint()
                if not self._queue_provenance_safe(expected_fingerprint):
                    exit_reason = "unsafe_pending_provenance"
                    break
                try:
                    self.outbox.public_activation_guard(
                        expected_runtime_provenance_sha256=expected_fingerprint
                    )
                except PublicActivationBoundaryError:
                    exit_reason = "public_activation_boundary_not_ready"
                    break

                if session is None or not session.verified:
                    if session is not None:
                        session.close()
                    session = self.session_factory(passcode=self._passcode)
                    try:
                        # Required arm check immediately before public connect.
                        if not self._armed():
                            exit_reason = "unarmed_before_connect"
                            break
                        session.connect_and_verify()
                        if not session.verified:
                            raise PreclaimConnectionError("VERIFIED_LOGIN_REQUIRED")
                        verified_connections += 1
                        backoff_index = 0
                    except AuthenticationRejected:
                        exit_reason = "authentication_rejected"
                        raise
                    except PreclaimConnectionError:
                        reconnect_failures += 1
                        session.close()
                        delay = self.backoff_seconds[min(backoff_index, len(self.backoff_seconds)-1)]
                        backoff_index = min(backoff_index + 1, len(self.backoff_seconds)-1)
                        self.sleep(delay)
                        cycles += 1
                        continue

                # Detect an already-closed session before creating an outbox claim.
                try:
                    session.poll_inbound(max_lines=100)
                except PreclaimConnectionError:
                    reconnect_failures += 1
                    session.close()
                    delay = self.backoff_seconds[min(backoff_index, len(self.backoff_seconds)-1)]
                    backoff_index = min(backoff_index + 1, len(self.backoff_seconds)-1)
                    self.sleep(delay)
                    cycles += 1
                    continue

                discarded = session.discarded
                comments = session.comments

                # Required arm check immediately before claim.
                if not self._armed():
                    exit_reason = "unarmed_before_claim"
                    break

                expected_fingerprint = self._runtime_fingerprint()
                try:
                    self.outbox.public_activation_guard(
                        expected_runtime_provenance_sha256=expected_fingerprint
                    )
                    claimed = self.outbox.claim_next(
                        now=self.now(),
                        expected_runtime_provenance_sha256=expected_fingerprint,
                    )
                except UnsafePendingProvenance:
                    exit_reason = "unsafe_pending_provenance"
                    break
                cycles += 1
                if claimed is None:
                    self.sleep(self.idle_poll_seconds)
                    continue

                claims += 1
                max_in_flight = max(max_in_flight, 1)
                key = str(claimed["uplink_key"])

                # Required arm check immediately before payload send. If it was
                # withdrawn after claim, no transport began; safe requeue.
                if not self._armed():
                    self.outbox.requeue_proven_not_started(key, error="LIVE_ARM_REMOVED_BEFORE_SEND")
                    requeues += 1
                    exit_reason = "unarmed_after_claim"
                    break

                # Re-measure immediately before payload send. Any provenance
                # measurement/validation failure at this point is provably
                # pre-transport, so safely requeue rather than leave a sending
                # row that would later become delivery_unknown.
                try:
                    send_fingerprint = self._runtime_fingerprint()
                except Exception:
                    self.outbox.requeue_proven_not_started(
                        key, error="RUNTIME_PROVENANCE_UNAVAILABLE_BEFORE_SEND"
                    )
                    requeues += 1
                    exit_reason = "runtime_provenance_changed_after_claim"
                    break
                if send_fingerprint != str(claimed.get("runtime_provenance_sha256") or ""):
                    self.outbox.requeue_proven_not_started(
                        key, error="RUNTIME_PROVENANCE_CHANGED_BEFORE_SEND"
                    )
                    requeues += 1
                    exit_reason = "runtime_provenance_changed_after_claim"
                    break

                try:
                    wire = _validate_live_wire(bytes(claimed["proposed_wire"]))
                    session.send_payload(wire)
                except TransportNotStarted as exc:
                    self.outbox.requeue_proven_not_started(key, error=str(exc))
                    requeues += 1
                    session.close()
                    self.sleep(self.min_seconds_between_claims)
                    continue
                except DeliveryUnknown as exc:
                    self.outbox.mark_delivery_unknown(key, now=self.now(), error=str(exc))
                    unknown += 1
                    session.close()
                    self.sleep(self.min_seconds_between_claims)
                    continue
                except Exception as exc:
                    self.outbox.mark_delivery_unknown(
                        key, now=self.now(), error=f"UNCLASSIFIED:{type(exc).__name__}"
                    )
                    unknown += 1
                    session.close()
                    self.sleep(self.min_seconds_between_claims)
                    continue

                try:
                    self.outbox.mark_sent(key, now=self.now())
                except Exception as exc:
                    # Payload was already handed to sendall. Never requeue.
                    try:
                        self.outbox.mark_delivery_unknown(
                            key,
                            now=self.now(),
                            error=f"POST_SEND_STATE_FAILURE:{type(exc).__name__}",
                        )
                        unknown += 1
                    finally:
                        session.close()
                    # If mark_delivery_unknown itself failed, a residual sending
                    # row remains and MUST be recovered on supervisor restart.
                    raise PersistentError("POST_SEND_STATE_TRANSITION_FAILED") from exc

                sent += 1
                try:
                    session.poll_inbound(max_lines=100)
                except PreclaimConnectionError:
                    # Send was already durably marked sent. Session loss affects
                    # only the next cycle, never this completed row.
                    session.close()
                discarded = session.discarded
                comments = session.comments
                self.sleep(self.min_seconds_between_claims)
        finally:
            if session is not None:
                discarded = max(discarded, session.discarded)
                comments = max(comments, session.comments)
                session.close()
                session.forget_credential()
            self._passcode = ""

        return PersistentRunSummary(
            persistent_version=PERSISTENT_VERSION,
            endpoint_host=ENDPOINT_HOST,
            endpoint_port=ENDPOINT_PORT,
            igate_call=IGATE_CALL,
            startup_recovered_sending=recovered,
            cycles=cycles,
            verified_connections=verified_connections,
            reconnect_failures=reconnect_failures,
            claims=claims,
            sent=sent,
            delivery_unknown=unknown,
            proven_not_started_requeues=requeues,
            inbound_packets_discarded=discarded,
            comments_received=comments,
            exit_reason=exit_reason,
            max_in_flight=max_in_flight,
        )


def self_check() -> dict[str, object]:
    return {
        "persistent_version": PERSISTENT_VERSION,
        "endpoint_host": ENDPOINT_HOST,
        "endpoint_port": ENDPOINT_PORT,
        "igate_call": IGATE_CALL,
        "outbox_db": OUTBOX_DB,
        "arm_marker": ARM_MARKER,
        "credential_source": "systemd_CREDENTIALS_DIRECTORY",
        "verified_login_before_claim": True,
        "max_claims_per_cycle": 1,
        "max_in_flight": 1,
        "single_worker_lease": WORKER_LOCK,
        "runtime_provenance_before_connect_claim_send": True,
        "unsafe_pending_provenance_blocks_before_connect": True,
        "min_seconds_between_claims": MIN_SECONDS_BETWEEN_CLAIMS,
        "startup_sending_recovery": "delivery_unknown",
        "ambiguous_send": "delivery_unknown_terminal_no_auto_retry",
        "inbound_aprs_is_action": "discard",
        "source_aprs_db_access": False,
        "aprs_is_to_rf": False,
        "cross_network_routing": False,
        "backoff_seconds": list(BACKOFF_SECONDS),
    }


def main() -> int:
    if len(sys.argv) != 1:
        print("C51_ARGUMENTS_FORBIDDEN", flush=True)
        return 2
    try:
        passcode = load_systemd_credential(CREDENTIAL_NAME)
        worker = PersistentWorker(passcode=passcode)
        passcode = ""
        summary = worker.run()
    except CredentialError as exc:
        print(f"C51_CREDENTIAL_ERROR={exc}", flush=True)
        return 3
    except AuthenticationRejected as exc:
        print(f"C51_AUTHENTICATION_REJECTED={exc}", flush=True)
        return 4
    except InvalidArmMarker as exc:
        print(f"C51_ARM_MARKER_INVALID={exc}", flush=True)
        return 5
    except WorkerLeaseHeld as exc:
        print(f"C51_WORKER_LEASE_HELD={exc}", flush=True)
        return 6
    except PersistentError as exc:
        print(f"C51_PERSISTENT_ERROR={exc}", flush=True)
        return 7
    finally:
        try:
            passcode = ""
        except UnboundLocalError:
            pass

    print("C51_RESULT=" + json.dumps(asdict(summary), sort_keys=True, separators=(",", ":")), flush=True)
    if summary.exit_reason.startswith("unarmed"):
        print("C51_EXIT_UNARMED=TRUE", flush=True)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
