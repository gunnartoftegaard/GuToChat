#!/usr/bin/env python3
"""Receive-only APRS-IS adapter for the GuToChat/GuToMap APRS pipeline.

APRS-A1.2 is intentionally narrow:
- TCP user-defined filtered feed (port 14580 by default).
- Receive-only login using pass -1.
- One range filter; no full-feed mode.
- No packet transmit API after the login line.
- Received TNC2 packets are parsed by aprs_parser and persisted by AprsStore.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import socket
import time
from typing import BinaryIO, Callable, Protocol

from aprs_parser import AprsParseError, parse_tnc2_line
from aprs_store import AprsStore


DEFAULT_HOST = "rotate.aprs2.net"
DEFAULT_PORT = 14580
DEFAULT_SOFTWARE = "GuToChat"
DEFAULT_SOFTWARE_VERSION = "2.5.0-beta4-A1.6"
MAX_WIRE_LINE_BYTES = 512
MAX_FILTER_LENGTH = 128

_LOGIN_RE = re.compile(r"^[A-Za-z0-9]{3,9}(?:-[A-Za-z0-9]{1,2})?$")
_RANGE_FILTER_RE = re.compile(
    r"^r/([+-]?(?:\d+(?:\.\d*)?|\.\d+))/"
    r"([+-]?(?:\d+(?:\.\d*)?|\.\d+))/"
    r"([+]?(?:\d+(?:\.\d*)?|\.\d+))$"
)
_Q_GATEWAY_TOKENS = {"qar", "qao"}


class AprsIsError(RuntimeError):
    """Base class for APRS-IS adapter failures."""


class AprsIsProtocolError(AprsIsError):
    """Raised when the peer violates the APRS-IS line/login contract."""


class SocketLike(Protocol):
    def settimeout(self, value: float | None) -> None: ...
    def makefile(self, mode: str) -> BinaryIO: ...
    def recv(self, size: int) -> bytes: ...
    def sendall(self, data: bytes) -> None: ...
    def close(self) -> None: ...


Connector = Callable[[tuple[str, int], float], SocketLike]


def _default_connector(address: tuple[str, int], timeout: float) -> SocketLike:
    return socket.create_connection(address, timeout=timeout)


def _compact_number(value: float, *, decimals: int = 5) -> str:
    text = f"{float(value):.{decimals}f}".rstrip("0").rstrip(".")
    if text in {"-0", "+0", ""}:
        return "0"
    return text


def build_range_filter(latitude: float, longitude: float, radius_km: float) -> str:
    """Build the APRS-IS ``r/lat/lon/dist`` subscription used by A1.2."""
    lat = float(latitude)
    lon = float(longitude)
    radius = float(radius_km)
    if not -90.0 <= lat <= 90.0:
        raise ValueError("APRS-IS range-filter latitude must be within -90..90")
    if not -180.0 <= lon <= 180.0:
        raise ValueError("APRS-IS range-filter longitude must be within -180..180")
    if not 0.1 <= radius <= 5000.0:
        raise ValueError("APRS-IS range-filter radius must be within 0.1..5000 km")
    return (
        f"r/{_compact_number(lat)}/{_compact_number(lon)}/"
        f"{_compact_number(radius, decimals=3)}"
    )


def validate_range_filter(value: str) -> str:
    """Validate and canonicalize the single range filter allowed by A1.2."""
    text = str(value or "").strip()
    if not text or len(text) > MAX_FILTER_LENGTH:
        raise ValueError("APRS-IS range filter is empty or too long")
    if "\r" in text or "\n" in text or any(ord(char) < 32 for char in text):
        raise ValueError("APRS-IS range filter contains control characters")
    match = _RANGE_FILTER_RE.fullmatch(text)
    if match is None:
        raise ValueError("APRS-A1.2 permits one r/lat/lon/dist range filter only")
    return build_range_filter(
        float(match.group(1)),
        float(match.group(2)),
        float(match.group(3)),
    )


def validate_aprs_is_login(value: str) -> str:
    """Validate the receive-only APRS-IS login identifier."""
    text = str(value or "").strip().upper()
    if not _LOGIN_RE.fullmatch(text) or len(text) > 9:
        raise ValueError("Invalid APRS-IS login identifier")
    if text.endswith("-0"):
        raise ValueError("APRS-IS login must not explicitly use SSID -0")
    # APRS-IS reserves exactly eight hexadecimal characters for generated
    # address identifiers in q constructs.
    if len(text) == 8 and all(char in "0123456789ABCDEF" for char in text):
        raise ValueError("APRS-IS login collides with reserved 8-hex identifier form")
    return text


def infer_aprs_is_gateway(tnc2_line: str) -> str:
    """Return RF-entry gateway following qAR/qAr/qAO/qAo, when present."""
    header = str(tnc2_line or "").split(":", 1)[0]
    if ">" not in header:
        return ""
    route = header.split(">", 1)[1].split(",")
    for index, token in enumerate(route[:-1]):
        if token.strip().lower() in _Q_GATEWAY_TOKENS:
            gateway = route[index + 1].strip().upper()
            if gateway and len(gateway) <= 16 and gateway.isprintable():
                return gateway
    return ""


@dataclass(frozen=True)
class AprsIsConfig:
    """Validated receive-only APRS-IS session configuration."""

    login: str
    range_filter: str
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    software_name: str = DEFAULT_SOFTWARE
    software_version: str = DEFAULT_SOFTWARE_VERSION
    connect_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 90.0

    def __post_init__(self) -> None:
        login = validate_aprs_is_login(self.login)
        range_filter = validate_range_filter(self.range_filter)
        host = str(self.host or "").strip()
        if not host or len(host) > 253 or any(char.isspace() for char in host):
            raise ValueError("Invalid APRS-IS host")
        port = int(self.port)
        if not 1 <= port <= 65535:
            raise ValueError("Invalid APRS-IS port")
        software_name = str(self.software_name or "").strip()
        software_version = str(self.software_version or "").strip()
        for label, value in (
            ("software name", software_name),
            ("software version", software_version),
        ):
            if not value or len(value) > 32 or any(char.isspace() for char in value):
                raise ValueError(f"Invalid APRS-IS {label}")
            if any(ord(char) < 33 or ord(char) > 126 for char in value):
                raise ValueError(f"Invalid APRS-IS {label}")
        connect_timeout = float(self.connect_timeout_seconds)
        read_timeout = float(self.read_timeout_seconds)
        if not 0.1 <= connect_timeout <= 120.0:
            raise ValueError("APRS-IS connect timeout must be within 0.1..120 seconds")
        if not 1.0 <= read_timeout <= 3600.0:
            raise ValueError("APRS-IS read timeout must be within 1..3600 seconds")

        object.__setattr__(self, "login", login)
        object.__setattr__(self, "range_filter", range_filter)
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "port", port)
        object.__setattr__(self, "software_name", software_name)
        object.__setattr__(self, "software_version", software_version)
        object.__setattr__(self, "connect_timeout_seconds", connect_timeout)
        object.__setattr__(self, "read_timeout_seconds", read_timeout)

    @classmethod
    def for_range(
        cls,
        *,
        login: str,
        latitude: float,
        longitude: float,
        radius_km: float,
        **kwargs: object,
    ) -> "AprsIsConfig":
        return cls(
            login=login,
            range_filter=build_range_filter(latitude, longitude, radius_km),
            **kwargs,
        )

    def login_line(self) -> str:
        """Return the only client-originated line permitted by A1.2."""
        return (
            f"user {self.login} pass -1 vers {self.software_name} "
            f"{self.software_version} filter {self.range_filter}"
        )


@dataclass
class AprsIsIngestStats:
    server_identification: str = ""
    login_response: str = ""
    comments_received: int = 0
    packets_received: int = 0
    parse_errors: int = 0
    positions_parsed: int = 0
    unsupported_positions: int = 0
    non_position_packets: int = 0
    stored_created: int = 0
    stored_updated: int = 0
    stored_duplicate: int = 0
    stored_older: int = 0
    stored_ignored: int = 0
    packet_limit_reached: bool = False
    time_limit_reached: bool = False
    elapsed_seconds: float = 0.0
    stop_requested: bool = False
    peer_eof: bool = False

    @property
    def stored_positions(self) -> int:
        return (
            self.stored_created
            + self.stored_updated
            + self.stored_duplicate
            + self.stored_older
        )


class AprsIsClient:
    """One receive-only APRS-IS session feeding the APRS parser/store."""

    def __init__(
        self,
        config: AprsIsConfig,
        store: AprsStore,
        *,
        connector: Connector | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self._connector = connector or _default_connector

    @staticmethod
    def _read_wire_line(reader: BinaryIO) -> bytes | None:
        raw = reader.readline(MAX_WIRE_LINE_BYTES + 1)
        if raw == b"":
            return None
        if len(raw) > MAX_WIRE_LINE_BYTES:
            raise AprsIsProtocolError("APRS-IS line exceeds 512-byte protocol limit")
        if not raw.endswith(b"\n"):
            raise AprsIsProtocolError("APRS-IS connection ended with an unterminated line")
        return raw.rstrip(b"\r\n")

    @staticmethod
    def _decode_wire_line(raw: bytes) -> str:
        # TNC2 headers are ASCII. Latin-1 preserves each received byte 1:1 for
        # comments/payloads without silently replacing octets before hashing.
        return raw.decode("latin-1", "strict")

    def _validate_login_response(self, line: str) -> None:
        match = re.match(
            r"^#\s*logresp\s+(\S+)\s+(verified|unverified),(?:\s|$)",
            line,
            re.IGNORECASE,
        )
        if match is None:
            raise AprsIsProtocolError("Malformed APRS-IS login response")
        if match.group(1).upper() != self.config.login:
            raise AprsIsProtocolError("APRS-IS login response names another client")
        # pass -1 is deliberately unverified. A verified response is harmless
        # for receive-only operation, but this client still exposes no send API.


    @staticmethod
    def _recv_wire_line_bounded(
        sock: SocketLike,
        buffer: bytearray,
        *,
        deadline: float,
        stop_requested: Callable[[], bool] | None = None,
    ) -> tuple[bytes | None, bool]:
        """Read one LF-terminated APRS-IS line with an absolute deadline.

        Returns ``(line, False)`` for one line, ``(None, False)`` when the
        deadline expires, and ``(None, True)`` on clean EOF. The buffer is
        byte-oriented so Mic-E control octets are never interpreted as line
        separators.
        """
        while True:
            if stop_requested is not None and stop_requested():
                return None, False
            newline = buffer.find(b"\n")
            if newline >= 0:
                wire_len = newline + 1
                if wire_len > MAX_WIRE_LINE_BYTES:
                    raise AprsIsProtocolError(
                        "APRS-IS line exceeds 512-byte protocol limit"
                    )
                raw = bytes(buffer[:wire_len])
                del buffer[:wire_len]
                return raw.rstrip(b"\r\n"), False

            if len(buffer) >= MAX_WIRE_LINE_BYTES:
                raise AprsIsProtocolError(
                    "APRS-IS line exceeds 512-byte protocol limit"
                )

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None, False

            sock.settimeout(min(1.0, max(0.05, remaining)))
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if chunk == b"":
                if buffer:
                    raise AprsIsProtocolError(
                        "APRS-IS connection ended with an unterminated line"
                    )
                return None, True
            buffer.extend(chunk)

    def _ingest_packet_line(
        self,
        line: str,
        stats: AprsIsIngestStats,
    ) -> None:
        stats.packets_received += 1
        try:
            packet = parse_tnc2_line(
                line,
                source_type="aprs_is",
                transport="unknown",
                source_gateway=infer_aprs_is_gateway(line),
            )
        except (AprsParseError, ValueError):
            stats.parse_errors += 1
            return

        if packet.parse_state == "position":
            stats.positions_parsed += 1
        elif packet.parse_state == "unsupported_position":
            stats.unsupported_positions += 1
        else:
            stats.non_position_packets += 1

        result = self.store.store_packet(packet)
        attr = f"stored_{result}"
        if not hasattr(stats, attr):
            raise AprsIsProtocolError(f"Unexpected APRS store result: {result!r}")
        setattr(stats, attr, getattr(stats, attr) + 1)

    def run_bounded(
        self,
        *,
        max_packets: int = 100,
        max_seconds: float = 120.0,
        on_packet: Callable[[str], None] | None = None,
        stop_requested: Callable[[], bool] | None = None,
    ) -> AprsIsIngestStats:
        """Run one receive-only APRS-IS session with packet and time limits.

        This method is intended for isolated A1.6 integration tests. It sends
        exactly the same single receive-only login line as :meth:`run_once`;
        after login there is no client-originated APRS data, message, command
        or filter update.
        """
        packet_limit = int(max_packets)
        time_limit = float(max_seconds)
        if not 1 <= packet_limit <= 1_000_000:
            raise ValueError("max_packets must be within 1..1000000")
        if not 1.0 <= time_limit <= 3600.0:
            raise ValueError("max_seconds must be within 1..3600")

        stats = AprsIsIngestStats()
        started = time.monotonic()
        deadline = started + time_limit
        sock = self._connector(
            (self.config.host, self.config.port),
            self.config.connect_timeout_seconds,
        )
        buffer = bytearray()
        try:
            first_raw, eof = self._recv_wire_line_bounded(
                sock, buffer, deadline=deadline, stop_requested=stop_requested
            )
            if first_raw is None:
                if stop_requested is not None and stop_requested():
                    stats.stop_requested = True
                    return stats
                if eof:
                    raise AprsIsProtocolError(
                        "APRS-IS closed before server identification"
                    )
                raise AprsIsProtocolError(
                    "APRS-IS server identification timed out"
                )
            first = self._decode_wire_line(first_raw)
            if not first.startswith("#"):
                raise AprsIsProtocolError(
                    "APRS-IS did not send a server identification comment"
                )
            stats.server_identification = first
            stats.comments_received += 1

            login_wire = (self.config.login_line() + "\r\n").encode(
                "ascii", "strict"
            )
            if len(login_wire) > MAX_WIRE_LINE_BYTES:
                raise AprsIsProtocolError(
                    "APRS-IS login line exceeds protocol limit"
                )
            sock.sendall(login_wire)

            logged_in = False
            while stats.packets_received < packet_limit:
                raw, eof = self._recv_wire_line_bounded(
                    sock, buffer, deadline=deadline, stop_requested=stop_requested
                )
                if raw is None:
                    if eof:
                        stats.peer_eof = True
                        break
                    if stop_requested is not None and stop_requested():
                        stats.stop_requested = True
                    else:
                        stats.time_limit_reached = True
                    break

                line = self._decode_wire_line(raw)
                if line.startswith("#"):
                    stats.comments_received += 1
                    if re.match(r"^#\s*logresp\b", line, re.IGNORECASE):
                        self._validate_login_response(line)
                        stats.login_response = line
                        logged_in = True
                    continue

                if not logged_in:
                    raise AprsIsProtocolError(
                        "APRS-IS delivered packet data before login acknowledgement"
                    )

                if on_packet is not None:
                    on_packet(line)
                self._ingest_packet_line(line, stats)

            if stats.packets_received >= packet_limit:
                stats.packet_limit_reached = True
            if not logged_in:
                raise AprsIsProtocolError(
                    "APRS-IS session ended before login acknowledgement"
                )
            return stats
        finally:
            stats.elapsed_seconds = max(0.0, time.monotonic() - started)
            sock.close()

    def run_once(self, *, max_packets: int | None = None) -> AprsIsIngestStats:
        """Connect once, ingest until EOF (or ``max_packets``), then return stats.

        ``max_packets`` is a local test/diagnostic bound. The client sends only
        the mandatory receive-only login line and has no method for sending APRS
        packets, messages, filter updates, or server commands after login.
        """
        if max_packets is not None and not 1 <= int(max_packets) <= 1_000_000:
            raise ValueError("max_packets must be within 1..1000000")

        stats = AprsIsIngestStats()
        sock = self._connector(
            (self.config.host, self.config.port),
            self.config.connect_timeout_seconds,
        )
        try:
            sock.settimeout(self.config.read_timeout_seconds)
            reader = sock.makefile("rb")
            try:
                first_raw = self._read_wire_line(reader)
                if first_raw is None:
                    raise AprsIsProtocolError("APRS-IS closed before server identification")
                first = self._decode_wire_line(first_raw)
                if not first.startswith("#"):
                    raise AprsIsProtocolError("APRS-IS did not send a server identification comment")
                stats.server_identification = first
                stats.comments_received += 1

                login_wire = (self.config.login_line() + "\r\n").encode("ascii", "strict")
                if len(login_wire) > MAX_WIRE_LINE_BYTES:
                    raise AprsIsProtocolError("APRS-IS login line exceeds protocol limit")
                sock.sendall(login_wire)

                logged_in = False
                while True:
                    raw = self._read_wire_line(reader)
                    if raw is None:
                        break
                    line = self._decode_wire_line(raw)
                    if line.startswith("#"):
                        stats.comments_received += 1
                        if re.match(r"^#\s*logresp\b", line, re.IGNORECASE):
                            self._validate_login_response(line)
                            stats.login_response = line
                            logged_in = True
                        continue

                    if not logged_in:
                        raise AprsIsProtocolError(
                            "APRS-IS delivered packet data before login acknowledgement"
                        )

                    self._ingest_packet_line(line, stats)

                    if max_packets is not None and stats.packets_received >= int(max_packets):
                        break

                if not logged_in:
                    raise AprsIsProtocolError("APRS-IS closed before login acknowledgement")
                return stats
            finally:
                try:
                    reader.close()
                except Exception:
                    pass
        finally:
            sock.close()
