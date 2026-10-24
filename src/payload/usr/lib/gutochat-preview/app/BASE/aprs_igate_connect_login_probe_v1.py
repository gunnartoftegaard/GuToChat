#!/usr/bin/env python3
"""C4.4 one-shot APRS-IS connect/login-only probe.

This module is intentionally NOT an uplink dispatcher. It has no outbox input,
no packet-send API and no runtime-selectable endpoint. The public network scope
is hard-locked to the APRS Tier 2 Europe/Africa rotate endpoint on port 14580.
The only transmitted application line is the APRS-IS login line.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
import socket
import sys
import time
from typing import Callable

from aprs_igate_credential_v1 import CredentialError, load_systemd_credential

PROBE_VERSION = "gutochat.aprs.igate.c4.4.login-probe.v1"
ENDPOINT_HOST = "euro.aprs2.net"
ENDPOINT_PORT = 14580
IGATE_CALL = "N0CALL"
CLIENT_NAME = "GuToChat"
CLIENT_VERSION = "2.5.0-beta4"
CREDENTIAL_NAME = "aprs-is-passcode"
MAX_SERVER_LINE_BYTES = 4096
CALL_RE = re.compile(r"^[A-Z0-9]{3,6}(?:-[A-Z0-9]{1,2})?$")
PASS_RE = re.compile(r"^[0-9]{1,5}$")
LOGRESP_RE = re.compile(
    r"^#\s*logresp\s+(?P<call>\S+)\s+(?P<state>verified|unverified)\b",
    re.IGNORECASE,
)


class ProbeError(RuntimeError):
    pass


class LoginRejected(ProbeError):
    pass


@dataclass(frozen=True)
class ProbeResult:
    probe_version: str
    endpoint_host: str
    endpoint_port: int
    peer_ip: str
    igate_call: str
    server_banner_seen: bool
    login_verified: bool
    comments_received: int
    inbound_packets_discarded: int
    payload_packets_sent: int
    outbox_accessed: bool


def _login_line(passcode: str) -> bytes:
    call = IGATE_CALL.strip().upper()
    if not CALL_RE.fullmatch(call):
        raise ProbeError("INVALID_FIXED_IGATE_CALL")
    text = str(passcode)
    if not PASS_RE.fullmatch(text) or not (0 <= int(text, 10) <= 32767):
        raise ProbeError("INVALID_CREDENTIAL_FORMAT")
    # Never return/log this line from status paths.
    return f"user {call} pass {text} vers {CLIENT_NAME} {CLIENT_VERSION}\r\n".encode("ascii")


def _parse_logresp(line: str) -> None:
    match = LOGRESP_RE.match(line.strip())
    if match is None:
        raise ProbeError("LOGIN_RESPONSE_MALFORMED")
    if match.group("call").upper() != IGATE_CALL:
        raise LoginRejected("LOGIN_RESPONSE_CALL_MISMATCH")
    if match.group("state").lower() != "verified":
        raise LoginRejected("LOGIN_UNVERIFIED")


def _recv_line(sock: socket.socket, buffer: bytearray, deadline: float) -> str:
    while True:
        pos = buffer.find(b"\n")
        if pos >= 0:
            raw = bytes(buffer[:pos+1])
            del buffer[:pos+1]
            if len(raw) > MAX_SERVER_LINE_BYTES:
                raise ProbeError("SERVER_LINE_TOO_LONG")
            return raw.rstrip(b"\r\n").decode("ascii", errors="replace")
        remain = deadline - time.monotonic()
        if remain <= 0:
            raise ProbeError("SERVER_LINE_TIMEOUT")
        sock.settimeout(min(remain, 0.5))
        try:
            chunk = sock.recv(2048)
        except socket.timeout:
            continue
        except OSError as exc:
            raise ProbeError("SOCKET_READ_FAILED") from exc
        if not chunk:
            raise ProbeError("SERVER_CLOSED")
        buffer.extend(chunk)
        if len(buffer) > MAX_SERVER_LINE_BYTES:
            raise ProbeError("SERVER_LINE_TOO_LONG")


def _connect_login_only(
    *,
    passcode: str,
    host: str = ENDPOINT_HOST,
    port: int = ENDPOINT_PORT,
    socket_factory: Callable[..., socket.socket] = socket.create_connection,
    connect_timeout: float = 8.0,
    login_timeout: float = 8.0,
    post_verify_drain_seconds: float = 1.0,
) -> ProbeResult:
    """Internal testable primitive; production CLI always uses fixed endpoint."""
    login = _login_line(passcode)
    sock: socket.socket | None = None
    buffer = bytearray()
    comments = 0
    discarded = 0
    banner_seen = False
    verified = False
    peer_ip = "UNKNOWN"
    try:
        try:
            sock = socket_factory((host, int(port)), timeout=connect_timeout)
        except OSError as exc:
            raise ProbeError("CONNECT_FAILED") from exc
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            peer = sock.getpeername()
            peer_ip = str(peer[0]) if isinstance(peer, tuple) and peer else str(peer)
        except OSError:
            peer_ip = "UNKNOWN"

        deadline = time.monotonic() + login_timeout
        while not banner_seen:
            line = _recv_line(sock, buffer, deadline)
            if line.startswith("#"):
                comments += 1
                banner_seen = True
            else:
                discarded += 1

        # The only sendall in this module: APRS-IS login line, never a packet.
        try:
            sock.sendall(login)
        except OSError as exc:
            raise ProbeError("LOGIN_WRITE_FAILED") from exc

        deadline = time.monotonic() + login_timeout
        while not verified:
            line = _recv_line(sock, buffer, deadline)
            if line.startswith("#"):
                comments += 1
                if LOGRESP_RE.match(line.strip()):
                    _parse_logresp(line)
                    verified = True
            else:
                # Explicitly discard inbound APRS-IS packet lines.
                discarded += 1

        # Briefly drain already-available inbound data; never route it anywhere.
        end = time.monotonic() + max(0.0, post_verify_drain_seconds)
        sock.settimeout(0.1)
        while time.monotonic() < end:
            try:
                chunk = sock.recv(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            buffer.extend(chunk)
            while b"\n" in buffer:
                pos = buffer.find(b"\n")
                raw = bytes(buffer[:pos+1])
                del buffer[:pos+1]
                line = raw.rstrip(b"\r\n").decode("ascii", errors="replace")
                if line.startswith("#"):
                    comments += 1
                else:
                    discarded += 1

        return ProbeResult(
            probe_version=PROBE_VERSION,
            endpoint_host=host,
            endpoint_port=int(port),
            peer_ip=peer_ip,
            igate_call=IGATE_CALL,
            server_banner_seen=banner_seen,
            login_verified=verified,
            comments_received=comments,
            inbound_packets_discarded=discarded,
            payload_packets_sent=0,
            outbox_accessed=False,
        )
    finally:
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        # Reduce lifetime of login material in Python references.
        login = b""


def main() -> int:
    if len(sys.argv) != 1:
        print("C44_ARGUMENTS_FORBIDDEN", flush=True)
        return 2
    try:
        passcode = load_systemd_credential(CREDENTIAL_NAME)
        result = _connect_login_only(passcode=passcode)
    except CredentialError as exc:
        print(f"C44_CREDENTIAL_ERROR={exc}", flush=True)
        return 3
    except LoginRejected as exc:
        print(f"C44_LOGIN_REJECTED={exc}", flush=True)
        return 4
    except ProbeError as exc:
        print(f"C44_PROBE_ERROR={exc}", flush=True)
        return 5
    finally:
        try:
            passcode = ""
        except UnboundLocalError:
            pass
    print("C44_RESULT=" + json.dumps(asdict(result), sort_keys=True, separators=(",", ":")), flush=True)
    print("C44_CONNECT_LOGIN_ONLY=PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
