#!/usr/bin/env python3
"""C4.1 isolated APRS-IS TCP transport for GuToChat.

This candidate is deliberately incapable of contacting a public APRS-IS host.
Only IPv4/IPv6 loopback literals are accepted.  A later, separately authorized
gate may replace that hard isolation boundary.

Security/delivery invariants:
* server banner is observed before login is sent;
* login must be explicitly ``verified`` for the expected callsign;
* no payload send is permitted before verified login;
* TNC2 payload is CR/LF terminated and <=512 bytes including CR/LF;
* any payload-send exception is DeliveryUnknown (never safe automatic retry);
* inbound APRS packet lines are counted and discarded, never routed locally;
* passcode is never included in status/repr/error text.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import select
import socket
import time
from typing import Callable

from aprs_igate_outbox_v1 import DeliveryUnknown, TransportNotStarted


TRANSPORT_VERSION = "gutchat.aprs.is.transport.c4.1.v1"
MAX_WIRE_BYTES = 512
MAX_SERVER_LINE_BYTES = 4096
DEFAULT_CLIENT_NAME = "GuToChat"
DEFAULT_CLIENT_VERSION = "2.5.0-beta4"


class AprsIsPreclaimError(RuntimeError):
    """Connection/authentication failed before an outbox claim is allowed."""


class AprsIsProtocolError(AprsIsPreclaimError):
    """APRS-IS peer violated the minimum login protocol contract."""


class AprsIsAuthRejected(AprsIsPreclaimError):
    """APRS-IS explicitly returned an unverified/mismatched login."""


@dataclass(frozen=True)
class AprsIsEndpoint:
    host: str
    port: int

    def __post_init__(self) -> None:
        if not isinstance(self.port, int) or not (1 <= self.port <= 65535):
            raise ValueError("INVALID_ENDPOINT_PORT")
        try:
            addr = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise ValueError("C41_ENDPOINT_MUST_BE_LOOPBACK_LITERAL") from exc
        if not addr.is_loopback:
            raise ValueError("C41_EXTERNAL_ENDPOINT_FORBIDDEN")


@dataclass(frozen=True)
class AprsIsSessionStatus:
    endpoint_host: str
    endpoint_port: int
    expected_call: str
    verified: bool
    server_banner_seen: bool
    comments_received: int
    inbound_packets_discarded: int


_LOGRESP_RE = re.compile(
    r"^#\s*logresp\s+(?P<call>\S+)\s+(?P<state>verified|unverified)\b",
    re.IGNORECASE,
)
_CALL_RE = re.compile(r"^[A-Z0-9]{1,6}(?:-[A-Z0-9]{1,2})?$")
_PASS_RE = re.compile(r"^[0-9]{1,5}$")


def _validate_call(call: str) -> str:
    value = str(call).strip().upper()
    if not _CALL_RE.fullmatch(value):
        raise ValueError("INVALID_APRS_IS_CALL")
    return value


def _validate_synthetic_or_runtime_passcode(passcode: str) -> str:
    # C4.1 uses synthetic numeric credentials only.  The value is intentionally
    # not retained in any dataclass/status representation.
    value = str(passcode).strip()
    if not _PASS_RE.fullmatch(value):
        raise ValueError("INVALID_APRS_IS_PASSCODE_FORMAT")
    return value


def build_login_line(
    *,
    call: str,
    passcode: str,
    client_name: str = DEFAULT_CLIENT_NAME,
    client_version: str = DEFAULT_CLIENT_VERSION,
) -> bytes:
    checked_call = _validate_call(call)
    checked_pass = _validate_synthetic_or_runtime_passcode(passcode)
    safe_name = str(client_name).strip()
    safe_version = str(client_version).strip()
    if not safe_name or any(ch.isspace() for ch in safe_name):
        raise ValueError("INVALID_CLIENT_NAME")
    if not safe_version or any(ch.isspace() for ch in safe_version):
        raise ValueError("INVALID_CLIENT_VERSION")
    line = f"user {checked_call} pass {checked_pass} vers {safe_name} {safe_version}\r\n"
    data = line.encode("ascii")
    if len(data) > MAX_WIRE_BYTES:
        raise ValueError("LOGIN_LINE_TOO_LONG")
    return data


def parse_logresp(line: str, *, expected_call: str) -> bool:
    match = _LOGRESP_RE.match(str(line).strip())
    if match is None:
        raise AprsIsProtocolError("LOGIN_RESPONSE_MALFORMED")
    call = match.group("call").upper()
    expected = _validate_call(expected_call)
    if call != expected:
        raise AprsIsAuthRejected("LOGIN_RESPONSE_CALL_MISMATCH")
    if match.group("state").lower() != "verified":
        raise AprsIsAuthRejected("LOGIN_UNVERIFIED")
    return True


def validate_payload_wire(wire: bytes) -> bytes:
    if not isinstance(wire, (bytes, bytearray, memoryview)):
        raise TypeError("WIRE_MUST_BE_BYTES")
    data = bytes(wire)
    if not data.endswith(b"\r\n"):
        raise TransportNotStarted("WIRE_MISSING_CRLF")
    if len(data) > MAX_WIRE_BYTES:
        raise TransportNotStarted("WIRE_EXCEEDS_512_BYTES")
    body = data[:-2]
    if not body or b"\r" in body or b"\n" in body:
        raise TransportNotStarted("WIRE_INVALID_LINE_FRAMING")
    try:
        body.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TransportNotStarted("WIRE_NOT_ASCII") from exc
    return data


class AprsIsTransport:
    """One verified isolated loopback APRS-IS session."""

    def __init__(
        self,
        *,
        endpoint: AprsIsEndpoint,
        call: str,
        passcode: str,
        connect_timeout: float = 3.0,
        login_timeout: float = 3.0,
        socket_factory: Callable[..., socket.socket] = socket.create_connection,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if connect_timeout <= 0 or login_timeout <= 0:
            raise ValueError("INVALID_TIMEOUT")
        self.endpoint = endpoint
        self.call = _validate_call(call)
        self._passcode = _validate_synthetic_or_runtime_passcode(passcode)
        self.connect_timeout = float(connect_timeout)
        self.login_timeout = float(login_timeout)
        self._socket_factory = socket_factory
        self._monotonic = monotonic
        self._sock: socket.socket | None = None
        self._buffer = bytearray()
        self._verified = False
        self._banner_seen = False
        self._comments = 0
        self._discarded = 0

    def __repr__(self) -> str:
        return (
            f"AprsIsTransport(endpoint={self.endpoint.host!r}:{self.endpoint.port},"
            f"call={self.call!r},verified={self._verified})"
        )

    @property
    def verified(self) -> bool:
        return self._verified

    def status(self) -> AprsIsSessionStatus:
        return AprsIsSessionStatus(
            endpoint_host=self.endpoint.host,
            endpoint_port=self.endpoint.port,
            expected_call=self.call,
            verified=self._verified,
            server_banner_seen=self._banner_seen,
            comments_received=self._comments,
            inbound_packets_discarded=self._discarded,
        )

    def close(self) -> None:
        sock, self._sock = self._sock, None
        self._verified = False
        self._buffer.clear()
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def __enter__(self) -> "AprsIsTransport":
        self.connect_and_verify()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        del exc_type, exc, tb
        self.close()

    def _readline_until(self, deadline: float) -> str:
        if self._sock is None:
            raise AprsIsPreclaimError("SOCKET_NOT_CONNECTED")
        while True:
            pos = self._buffer.find(b"\n")
            if pos >= 0:
                raw = bytes(self._buffer[: pos + 1])
                del self._buffer[: pos + 1]
                if len(raw) > MAX_SERVER_LINE_BYTES:
                    raise AprsIsProtocolError("SERVER_LINE_TOO_LONG")
                return raw.rstrip(b"\r\n").decode("ascii", errors="replace")
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise AprsIsPreclaimError("SERVER_LINE_TIMEOUT")
            self._sock.settimeout(min(remaining, 0.5))
            try:
                chunk = self._sock.recv(2048)
            except socket.timeout:
                continue
            except OSError as exc:
                raise AprsIsPreclaimError("SOCKET_READ_FAILED") from exc
            if not chunk:
                raise AprsIsPreclaimError("SERVER_CLOSED_BEFORE_VERIFIED_LOGIN")
            self._buffer.extend(chunk)
            if len(self._buffer) > MAX_SERVER_LINE_BYTES:
                raise AprsIsProtocolError("SERVER_LINE_TOO_LONG")

    def connect_and_verify(self) -> None:
        if self._verified and self._sock is not None:
            return
        self.close()
        # Each TCP connection must establish its own server-banner evidence.
        self._banner_seen = False
        try:
            sock = self._socket_factory(
                (self.endpoint.host, self.endpoint.port),
                timeout=self.connect_timeout,
            )
        except OSError as exc:
            raise AprsIsPreclaimError("CONNECT_FAILED") from exc
        self._sock = sock
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            banner_deadline = self._monotonic() + self.login_timeout
            while not self._banner_seen:
                line = self._readline_until(banner_deadline)
                if line.startswith("#"):
                    self._comments += 1
                    self._banner_seen = True
                else:
                    self._discarded += 1

            login = build_login_line(call=self.call, passcode=self._passcode)
            try:
                sock.sendall(login)
            except OSError as exc:
                raise AprsIsPreclaimError("LOGIN_WRITE_FAILED") from exc

            login_deadline = self._monotonic() + self.login_timeout
            while True:
                line = self._readline_until(login_deadline)
                if line.startswith("#"):
                    self._comments += 1
                    if _LOGRESP_RE.match(line.strip()):
                        parse_logresp(line, expected_call=self.call)
                        self._verified = True
                        return
                    continue
                self._discarded += 1
        except Exception:
            self.close()
            raise

    def poll_inbound(self, *, max_lines: int = 100) -> int:
        """Drain ready inbound lines; packet lines are discarded, never routed."""
        if max_lines <= 0 or max_lines > 1000:
            raise ValueError("INVALID_MAX_LINES")
        if self._sock is None or not self._verified:
            return 0
        processed = 0
        while processed < max_lines:
            pos = self._buffer.find(b"\n")
            if pos < 0:
                try:
                    ready, _, _ = select.select([self._sock], [], [], 0)
                except (OSError, ValueError):
                    self.close()
                    break
                if not ready:
                    break
                try:
                    chunk = self._sock.recv(2048)
                except (BlockingIOError, socket.timeout):
                    break
                except OSError:
                    self.close()
                    break
                if not chunk:
                    self.close()
                    break
                self._buffer.extend(chunk)
                if len(self._buffer) > MAX_SERVER_LINE_BYTES:
                    self.close()
                    raise AprsIsProtocolError("SERVER_LINE_TOO_LONG")
                continue
            raw = bytes(self._buffer[: pos + 1])
            del self._buffer[: pos + 1]
            line = raw.rstrip(b"\r\n").decode("ascii", errors="replace")
            if line.startswith("#"):
                self._comments += 1
            else:
                self._discarded += 1
            processed += 1
        return processed

    def send(self, wire: bytes, *, uplink_key: str) -> None:
        del uplink_key  # key is an outbox identity only; never sent on wire.
        if self._sock is None or not self._verified:
            raise TransportNotStarted("APRS_IS_SESSION_NOT_VERIFIED")
        data = validate_payload_wire(wire)
        try:
            self._sock.sendall(data)
        except OSError as exc:
            self.close()
            raise DeliveryUnknown("APRS_IS_PAYLOAD_WRITE_AMBIGUOUS") from exc
        # Best-effort inbound drain only.  APRS-IS has no per-packet ACK, so a
        # successful sendall is the strongest application-level completion
        # signal available to this transport.
        self.poll_inbound(max_lines=100)


def self_check() -> dict[str, object]:
    return {
        "transport_version": TRANSPORT_VERSION,
        "external_endpoint_allowed": False,
        "loopback_literal_required": True,
        "verified_login_required_before_send": True,
        "max_wire_bytes": MAX_WIRE_BYTES,
        "inbound_packet_action": "discard",
        "credential_in_status": False,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(self_check(), sort_keys=True, separators=(",", ":")))
