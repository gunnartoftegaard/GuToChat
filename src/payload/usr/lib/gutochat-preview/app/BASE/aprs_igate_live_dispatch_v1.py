#!/usr/bin/env python3
"""C4.5 one-shot live APRS-IS dispatcher for GuToChat receive-only iGate.

Hard contract:
- fixed public endpoint euro.aprs2.net:14580
- fixed iGate login N0CALL
- verified APRS-IS login BEFORE any outbox claim
- claim at most one queued outbox row
- transmit only a pre-approved qAO,N0CALL TNC2 line
- never read the source APRS database
- never route APRS-IS inbound traffic anywhere
- ambiguous payload write becomes terminal delivery_unknown; never auto-retry
- no CLI parameters; credential comes only from systemd CREDENTIALS_DIRECTORY
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import re
import socket
import sys
import time
from typing import Callable

from aprs_igate_credential_v1 import CredentialError, load_systemd_credential
from aprs_igate_outbox_v1 import (
    DeliveryUnknown, IgateOutbox, TransportNotStarted, UnsafePendingProvenance,
    PublicActivationBoundaryError,
)
from aprs_igate_policy_v1_rev2 import runtime_provenance_fingerprint, runtime_provenance_matches_expected
from aprs_igate_provenance_v1 import measure_runtime_provenance
from aprs_igate_uplink_lease_v1 import WORKER_LOCK, worker_lease

DISPATCH_VERSION = "gutochat.aprs.igate.c4.5.live-dispatch.v1"
ENDPOINT_HOST = "euro.aprs2.net"
ENDPOINT_PORT = 14580
IGATE_CALL = "N0CALL"
CLIENT_NAME = "GuToChat"
CLIENT_VERSION = "2.5.0-beta4"
CREDENTIAL_NAME = "aprs-is-passcode"
OUTBOX_DB = "/var/lib/gutochat-aprs-igate/igate_outbox.db"
MAX_WIRE_BYTES = 512
MAX_SERVER_LINE_BYTES = 4096
CALL_RE = re.compile(r"^[A-Z0-9]{3,6}(?:-[A-Z0-9]{1,2})?$")
PASS_RE = re.compile(r"^[0-9]{1,5}$")
Q_RE = re.compile(r"^qA[A-Z]$", re.IGNORECASE)
LOGRESP_RE = re.compile(
    r"^#\s*logresp\s+(?P<call>\S+)\s+(?P<state>verified|unverified)\b",
    re.IGNORECASE,
)


class DispatchError(RuntimeError):
    pass


class LoginRejected(DispatchError):
    pass


@dataclass(frozen=True)
class DispatchResult:
    dispatch_version: str
    endpoint_host: str
    endpoint_port: int
    peer_ip: str
    igate_call: str
    server_banner_seen: bool
    login_verified: bool
    outbox_accessed: bool
    outbox_claimed: bool
    source_sequence: int | None
    uplink_key: str | None
    payload_packets_sent: int
    outcome: str
    inbound_packets_discarded: int
    comments_received: int


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _login_line(passcode: str) -> bytes:
    if not CALL_RE.fullmatch(IGATE_CALL):
        raise DispatchError("INVALID_FIXED_IGATE_CALL")
    text = str(passcode)
    if not PASS_RE.fullmatch(text) or not (0 <= int(text, 10) <= 32767):
        raise DispatchError("INVALID_CREDENTIAL_FORMAT")
    return f"user {IGATE_CALL} pass {text} vers {CLIENT_NAME} {CLIENT_VERSION}\r\n".encode("ascii")


def _parse_logresp(line: str) -> None:
    m = LOGRESP_RE.match(line.strip())
    if m is None:
        raise DispatchError("LOGIN_RESPONSE_MALFORMED")
    if m.group("call").upper() != IGATE_CALL:
        raise LoginRejected("LOGIN_RESPONSE_CALL_MISMATCH")
    if m.group("state").lower() != "verified":
        raise LoginRejected("LOGIN_UNVERIFIED")


def _recv_line(sock: socket.socket, buffer: bytearray, deadline: float) -> str:
    while True:
        pos = buffer.find(b"\n")
        if pos >= 0:
            raw = bytes(buffer[:pos + 1])
            del buffer[:pos + 1]
            if len(raw) > MAX_SERVER_LINE_BYTES:
                raise DispatchError("SERVER_LINE_TOO_LONG")
            return raw.rstrip(b"\r\n").decode("ascii", errors="replace")
        remain = deadline - time.monotonic()
        if remain <= 0:
            raise DispatchError("SERVER_LINE_TIMEOUT")
        sock.settimeout(min(remain, 0.5))
        try:
            chunk = sock.recv(2048)
        except socket.timeout:
            continue
        except OSError as exc:
            raise DispatchError("SOCKET_READ_FAILED") from exc
        if not chunk:
            raise DispatchError("SERVER_CLOSED")
        buffer.extend(chunk)
        if len(buffer) > MAX_SERVER_LINE_BYTES:
            raise DispatchError("SERVER_LINE_TOO_LONG")


def _validate_live_wire(wire: bytes) -> bytes:
    """Fail closed before payload send. Safe failures prove transport not started."""
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
    for hop in path[:-2]:
        bare = hop.rstrip("*").upper()
        if bare in {"TCPIP", "TCPXX", "NOGATE", "RFONLY", "I"}:
            raise TransportNotStarted("WIRE_FORBIDDEN_PATH_TOKEN")
        if Q_RE.fullmatch(bare):
            raise TransportNotStarted("WIRE_PREEXISTING_Q_CONSTRUCT")
    if sum(1 for hop in path if hop.upper() == "QAO") != 1:
        raise TransportNotStarted("WIRE_QAO_COUNT_INVALID")
    return data


class VerifiedSession:
    def __init__(
        self,
        *,
        passcode: str,
        host: str = ENDPOINT_HOST,
        port: int = ENDPOINT_PORT,
        socket_factory: Callable[..., socket.socket] = socket.create_connection,
        connect_timeout: float = 8.0,
        login_timeout: float = 8.0,
    ) -> None:
        self._login = _login_line(passcode)
        self.host = host
        self.port = int(port)
        self.socket_factory = socket_factory
        self.connect_timeout = float(connect_timeout)
        self.login_timeout = float(login_timeout)
        self.sock: socket.socket | None = None
        self.buffer = bytearray()
        self.banner_seen = False
        self.verified = False
        self.comments = 0
        self.discarded = 0
        self.peer_ip = "UNKNOWN"

    def connect_and_verify(self) -> None:
        if self.host != ENDPOINT_HOST or self.port != ENDPOINT_PORT:
            raise DispatchError("PUBLIC_ENDPOINT_NOT_AUTHORIZED")
        try:
            self.sock = self.socket_factory((self.host, self.port), timeout=self.connect_timeout)
        except OSError as exc:
            raise DispatchError("CONNECT_FAILED") from exc
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            peer = self.sock.getpeername()
            self.peer_ip = str(peer[0]) if isinstance(peer, tuple) and peer else str(peer)
        except OSError:
            self.peer_ip = "UNKNOWN"

        deadline = time.monotonic() + self.login_timeout
        while not self.banner_seen:
            line = _recv_line(self.sock, self.buffer, deadline)
            if line.startswith("#"):
                self.comments += 1
                self.banner_seen = True
            else:
                self.discarded += 1

        try:
            self.sock.sendall(self._login)
        except OSError as exc:
            raise DispatchError("LOGIN_WRITE_FAILED") from exc

        deadline = time.monotonic() + self.login_timeout
        while not self.verified:
            line = _recv_line(self.sock, self.buffer, deadline)
            if line.startswith("#"):
                self.comments += 1
                if LOGRESP_RE.match(line.strip()):
                    _parse_logresp(line)
                    self.verified = True
            else:
                self.discarded += 1

    def send_payload(self, wire: bytes) -> None:
        if self.sock is None or not self.verified:
            raise TransportNotStarted("SESSION_NOT_VERIFIED")
        data = _validate_live_wire(wire)
        try:
            self.sock.sendall(data)
        except OSError as exc:
            # sendall() may have written a prefix; delivery is therefore ambiguous.
            raise DeliveryUnknown("PAYLOAD_WRITE_AMBIGUOUS") from exc

    def close(self) -> None:
        sock, self.sock = self.sock, None
        self.verified = False
        self._login = b""
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


def _run_one_unleased(
    *,
    passcode: str,
    outbox_db: str = OUTBOX_DB,
    session_factory=VerifiedSession,
    provenance_provider=measure_runtime_provenance,
) -> DispatchResult:
    outbox = IgateOutbox(outbox_db)
    provenance = provenance_provider()
    if not runtime_provenance_matches_expected(provenance):
        raise DispatchError("RUNTIME_PROVENANCE_MISMATCH_PRECONNECT")
    fingerprint = runtime_provenance_fingerprint(provenance)
    pending = outbox.pending_provenance_counts(expected_runtime_provenance_sha256=fingerprint)
    if not pending.get("schema_ready") or pending["unsafe"]:
        raise DispatchError("OUTBOX_PENDING_PROVENANCE_UNVERIFIED_OR_MISMATCH")
    try:
        outbox.public_activation_guard(expected_runtime_provenance_sha256=fingerprint)
    except PublicActivationBoundaryError as exc:
        raise DispatchError("PUBLIC_ACTIVATION_BOUNDARY_NOT_READY") from exc
    session = session_factory(passcode=passcode)
    claimed = None
    try:
        # Public connection is allowed only after provenance/queue safety passes;
        # verified login still occurs before the actual outbox claim.
        session.connect_and_verify()
        if not session.verified:
            raise DispatchError("VERIFIED_LOGIN_REQUIRED")

        try:
            outbox.public_activation_guard(expected_runtime_provenance_sha256=fingerprint)
            claimed = outbox.claim_next(
                now=_utcnow(),
                expected_runtime_provenance_sha256=fingerprint,
            )
        except UnsafePendingProvenance as exc:
            raise DispatchError("OUTBOX_PENDING_PROVENANCE_UNVERIFIED_OR_MISMATCH") from exc
        if claimed is None:
            return DispatchResult(
                DISPATCH_VERSION, ENDPOINT_HOST, ENDPOINT_PORT, session.peer_ip,
                IGATE_CALL, session.banner_seen, True, True, False,
                None, None, 0, "empty", session.discarded, session.comments,
            )

        key = str(claimed["uplink_key"])
        seq = int(claimed["source_sequence"])
        try:
            wire = _validate_live_wire(bytes(claimed["proposed_wire"]))
            session.send_payload(wire)
        except TransportNotStarted as exc:
            outbox.requeue_proven_not_started(key, error=str(exc))
            return DispatchResult(
                DISPATCH_VERSION, ENDPOINT_HOST, ENDPOINT_PORT, session.peer_ip,
                IGATE_CALL, session.banner_seen, True, True, True,
                seq, key, 0, "requeued_not_started", session.discarded, session.comments,
            )
        except DeliveryUnknown as exc:
            outbox.mark_delivery_unknown(key, now=_utcnow(), error=str(exc))
            return DispatchResult(
                DISPATCH_VERSION, ENDPOINT_HOST, ENDPOINT_PORT, session.peer_ip,
                IGATE_CALL, session.banner_seen, True, True, True,
                seq, key, 0, "delivery_unknown", session.discarded, session.comments,
            )
        except Exception as exc:
            outbox.mark_delivery_unknown(
                key, now=_utcnow(), error=f"UNCLASSIFIED:{type(exc).__name__}"
            )
            return DispatchResult(
                DISPATCH_VERSION, ENDPOINT_HOST, ENDPOINT_PORT, session.peer_ip,
                IGATE_CALL, session.banner_seen, True, True, True,
                seq, key, 0, "delivery_unknown", session.discarded, session.comments,
            )

        try:
            outbox.mark_sent(key, now=_utcnow())
        except Exception as exc:
            # Payload write completed but durable sent transition failed. Delivery
            # is necessarily ambiguous; conservatively terminalize if possible.
            try:
                outbox.mark_delivery_unknown(
                    key, now=_utcnow(), error=f"POST_SEND_STATE_FAILURE:{type(exc).__name__}"
                )
            except Exception:
                # A supervising runner must recover any remaining sending row to
                # delivery_unknown. Never report success in this branch.
                pass
            return DispatchResult(
                DISPATCH_VERSION, ENDPOINT_HOST, ENDPOINT_PORT, session.peer_ip,
                IGATE_CALL, session.banner_seen, True, True, True,
                seq, key, 0, "delivery_unknown", session.discarded, session.comments,
            )
        return DispatchResult(
            DISPATCH_VERSION, ENDPOINT_HOST, ENDPOINT_PORT, session.peer_ip,
            IGATE_CALL, session.banner_seen, True, True, True,
            seq, key, 1, "sent", session.discarded, session.comments,
        )
    finally:
        session.close()


def _run_one(
    *,
    passcode: str,
    outbox_db: str = OUTBOX_DB,
    session_factory=VerifiedSession,
    provenance_provider=measure_runtime_provenance,
    worker_lock_path: str | Path = WORKER_LOCK,
) -> DispatchResult:
    with worker_lease(worker_lock_path):
        return _run_one_unleased(
            passcode=passcode,
            outbox_db=outbox_db,
            session_factory=session_factory,
            provenance_provider=provenance_provider,
        )


def main() -> int:
    if len(sys.argv) != 1:
        print("C45_ARGUMENTS_FORBIDDEN", flush=True)
        return 2
    try:
        passcode = load_systemd_credential(CREDENTIAL_NAME)
        result = _run_one(passcode=passcode)
    except CredentialError as exc:
        print(f"C45_CREDENTIAL_ERROR={exc}", flush=True)
        return 3
    except LoginRejected as exc:
        print(f"C45_LOGIN_REJECTED={exc}", flush=True)
        return 4
    except DispatchError as exc:
        print(f"C45_PRECLAIM_ERROR={exc}", flush=True)
        return 5
    finally:
        try:
            passcode = ""
        except UnboundLocalError:
            pass

    print("C45_RESULT=" + json.dumps(asdict(result), sort_keys=True, separators=(",", ":")), flush=True)
    if result.outcome == "sent" and result.payload_packets_sent == 1:
        print("C45_CONTROLLED_LIVE_DISPATCH=PASS", flush=True)
        return 0
    if result.outcome == "empty":
        print("C45_NO_QUEUED_ROW=TRUE", flush=True)
        return 6
    if result.outcome == "requeued_not_started":
        print("C45_PAYLOAD_NOT_STARTED_REQUEUED=TRUE", flush=True)
        return 7
    if result.outcome == "delivery_unknown":
        print("C45_DELIVERY_UNKNOWN_TERMINAL=TRUE", flush=True)
        return 8
    print("C45_UNEXPECTED_OUTCOME", flush=True)
    return 9


if __name__ == "__main__":
    raise SystemExit(main())
