#!/usr/bin/env python3
"""LoRa Chat structured control protocols.

LC3 is the compact default used by LoRa Chat 2.1.  It carries UTF-8 fields
with lightweight escaping instead of base64 and uses short command/route
codes.  The LC2 parser and optional LC2 encoders remain for Base-first
upgrades and rollback interoperability.

Large LC3 control frames can be split into at most four ``F`` frames.  Each
fragment is independently transported and acknowledged by the private
Waveshare layer; :class:`FragmentAssembler` validates the complete frame with
CRC32 before it is acted upon.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
import zlib
from dataclasses import dataclass, field
from typing import Any, Protocol

LC2_PREFIX = "~LC2|"
LC3_PREFIX = "~L3|"
CONTROL_PREFIX = LC3_PREFIX
PROTOCOL_VERSION = "3.0"
MAX_FRAGMENTS = 4
LC3_AUTH_COMMAND = "Z"
LC3_AUTH_VERSION = "1"
LC3_AUTH_MAX_SKEW_SECONDS = 300
LC3_AUTH_DOMAIN = b"GUTOCHAT-LC3-AUTH-v1\0"
LC3_STATUS_AUTH_COMMAND = "Y"
LC3_STATUS_AUTH_VERSION = "1"
LC3_STATUS_AUTH_DOMAIN = b"GUTOCHAT-LC3-STATUS-AUTH-v1\0"

APRS_WIRE_VERSION = 2
APRS_WIRE_COMMENT_MAX_BYTES = 80
APRS_WIRE_PATH_MAX_ITEMS = 4
APRS_WIRE_PATH_ITEM_MAX_BYTES = 12
APRS_WIRE_OBSERVATION_HASH_PREFIX = "h:"


def _truncate_utf8(value: Any, max_bytes: int) -> str:
    text = str(value or "")
    raw = text.encode("utf-8")
    if len(raw) <= int(max_bytes):
        return text
    return raw[: int(max_bytes)].decode("utf-8", errors="ignore")


def _aprs_wire_path(value: Any) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value or "[]")
        except json.JSONDecodeError:
            value = []
    if not isinstance(value, list):
        value = []
    return [
        _truncate_utf8(item, APRS_WIRE_PATH_ITEM_MAX_BYTES)
        for item in value[:APRS_WIRE_PATH_MAX_ITEMS]
        if str(item or "").strip()
    ]


def compact_aprs_payload(payload: dict[str, Any]) -> list[Any]:
    """Return the bounded APRS presentation wire vector used by P3 rev3.

    Raw TNC2 is deliberately absent. Long presentation-only strings are
    bounded before compression so every valid observation can be proven to
    fit the operational four-fragment LC3 transport contract.
    """
    station = _truncate_utf8(payload.get("station_id"), 20).strip().upper()
    if not station:
        raise ValueError("APRS_WIRE_STATION_REQUIRED")
    try:
        latitude = round(float(payload["latitude"]), 6)
        longitude = round(float(payload["longitude"]), 6)
        received_epoch = int(payload["received_epoch"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("APRS_WIRE_POSITION_INVALID") from exc
    if not (-90.0 <= latitude <= 90.0 and -180.0 <= longitude <= 180.0 and received_epoch >= 0):
        raise ValueError("APRS_WIRE_POSITION_INVALID")
    observation_source = str(payload.get("observation_key") or "")
    if not observation_source:
        observation_source = f"{station}|{received_epoch}|{latitude:.6f}|{longitude:.6f}"
    observation_hash = APRS_WIRE_OBSERVATION_HASH_PREFIX + _b64_bytes_encode(
        hashlib.sha256(observation_source.encode("utf-8")).digest()[:16]
    )
    return [
        APRS_WIRE_VERSION,
        station, latitude, longitude,
        payload.get("altitude_m"), payload.get("course_deg"), payload.get("speed_kmh"),
        _truncate_utf8(payload.get("symbol_table") or "/", 1)[:1] or "/",
        _truncate_utf8(payload.get("symbol_code") or ">", 1)[:1] or ">",
        _truncate_utf8(payload.get("packet_time_raw"), 12),
        received_epoch,
        _truncate_utf8(payload.get("source_type") or "replicated", 16),
        _truncate_utf8(payload.get("transport") or "unknown", 10),
        _truncate_utf8(payload.get("source_gateway"), 16),
        _aprs_wire_path(payload.get("packet_path", [])),
        _truncate_utf8(payload.get("comment"), APRS_WIRE_COMMENT_MAX_BYTES),
        observation_hash,
        _truncate_utf8(payload.get("position_format") or "uncompressed", 12),
        payload.get("wind_direction_deg"), payload.get("wind_speed_kmh"), payload.get("gust_kmh"),
        payload.get("temperature_c"), payload.get("rain_last_hour_mm"), payload.get("rain_last_24h_mm"),
        payload.get("rain_since_midnight_mm"), payload.get("humidity_percent"), payload.get("pressure_hpa"),
    ]


def expand_aprs_payload(value: Any) -> dict[str, Any]:
    """Expand P3 rev3 compact APRS vectors; accept legacy dict payloads read-only."""
    if isinstance(value, dict):
        return dict(value)
    if not isinstance(value, list) or len(value) != 27 or int(value[0]) != APRS_WIRE_VERSION:
        raise ValueError("APRS_WIRE_VECTOR_INVALID")
    names = (
        "station_id", "latitude", "longitude", "altitude_m", "course_deg", "speed_kmh",
        "symbol_table", "symbol_code", "packet_time_raw", "received_epoch",
        "source_type", "transport", "source_gateway", "packet_path", "comment",
        "observation_key", "position_format", "wind_direction_deg", "wind_speed_kmh",
        "gust_kmh", "temperature_c", "rain_last_hour_mm", "rain_last_24h_mm",
        "rain_since_midnight_mm", "humidity_percent", "pressure_hpa",
    )
    result = {name: value[index + 1] for index, name in enumerate(names)}
    epoch = int(result.get("received_epoch") or 0)
    result["received_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)) if epoch else ""
    return result

_ROUTE_TO_WIRE = {"mesh868": "8", "mesh433": "4"}
_WIRE_TO_ROUTE = {value: key for key, value in _ROUTE_TO_WIRE.items()}
_NODE_ID_RE = re.compile(r"^[0-9a-fA-F]{8}$")

_MESSAGE_KEY_TO_WIRE = {
    "id": "i",
    "message_uid": "u",
    "timestamp": "t",
    "direction": "d",
    "source": "s",
    "destination": "o",
    "broadcast": "b",
    "text": "x",
    "packet_rssi": "r",
    "status": "q",
    "ack_rssi": "a",
    "attempts": "n",
    "updated_at": "v",
    "network": "w",
    "source_label": "l",
    "destination_label": "k",
    "snr": "g",
    "channel": "c",
    "gateway_request_id": "p",
}
_MESSAGE_WIRE_TO_KEY = {value: key for key, value in _MESSAGE_KEY_TO_WIRE.items()}

_POSITION_KEY_TO_WIRE = {
    "node_id": "i",
    "num": "n",
    "latitude_i": "a",
    "longitude_i": "o",
    "altitude": "h",
    "position_epoch": "t",
    "position_time_source": "u",
    "received_at": "r",
    "received_epoch": "e",
    "location_source": "l",
    "altitude_source": "v",
    "precision_bits": "p",
    "sats_in_view": "s",
    "fix_quality": "q",
    "fix_type": "f",
    "channel": "c",
    "rx_rssi": "d",
    "rx_snr": "g",
    "packet_id": "k",
    "source": "x",
    "updated_at": "w",
    "stored_at": "j",
}
_POSITION_WIRE_TO_KEY = {value: key for key, value in _POSITION_KEY_TO_WIRE.items()}


def compact_position_payload(payload: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in payload.items():
        if key not in _POSITION_KEY_TO_WIRE:
            continue
        if value in (None, "") and key not in {"packet_id"}:
            continue
        result[_POSITION_KEY_TO_WIRE[key]] = value
    return result


def expand_position_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        _POSITION_WIRE_TO_KEY.get(key, key): value
        for key, value in payload.items()
    }


def compact_message_payload(payload: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in payload.items():
        if key not in _MESSAGE_KEY_TO_WIRE:
            continue
        if value in (None, "") and key not in {"text", "source_label", "destination_label"}:
            continue
        if key == "broadcast" and not value:
            continue
        if key == "attempts" and int(value or 1) == 1:
            continue
        result[_MESSAGE_KEY_TO_WIRE[key]] = value
    return result


def expand_message_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        _MESSAGE_WIRE_TO_KEY.get(key, key): value
        for key, value in payload.items()
    }


def _b64_encode(value: str) -> str:
    raw = value.encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64_decode(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii")).decode(
        "utf-8", errors="replace"
    )


def _b64_bytes_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64_bytes_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def escape_field(value: Any) -> str:
    """Escape one LC3 field without expanding ordinary Norwegian text."""
    text = str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def split_escaped(value: str) -> list[str]:
    """Split an LC3 body and decode its lightweight field escaping."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            if char == "n":
                current.append("\n")
            elif char == "r":
                current.append("\r")
            else:
                current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "|":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def _lc3(command: str, *fields: Any) -> str:
    values = [command, *(escape_field(field) for field in fields)]
    return LC3_PREFIX + "|".join(values)


class ReplayStore(Protocol):
    def check_and_remember(
        self,
        key_id: str,
        nonce: str,
        authenticated_epoch: int,
        *,
        current_epoch: int,
        max_skew_seconds: int,
    ) -> bool: ...


@dataclass(frozen=True)
class AuthenticatedControl:
    """One verified LC3 authentication envelope.

    Authentication is deliberately separate from :func:`parse_control` so
    stored historical control rows can still be rendered without treating a
    second UI read as a network replay.  Live consumers decide when freshness
    and replay checks are required.
    """

    text: str
    key_id: str
    timestamp: int
    nonce: str


class ControlAuthenticator:
    """Optional HMAC-SHA256 authentication for complete LC3 control frames.

    The feature is inactive unless ``GUTOCHAT_LC3_AUTH_KEY`` is present.
    A key can therefore be deployed first without changing on-air traffic.
    ``GUTOCHAT_LC3_AUTH_SEND=1`` enables signed outbound frames and
    ``GUTOCHAT_LC3_AUTH_REQUIRED=1`` rejects unsigned live LC3 controls.

    The HMAC is truncated to 128 bits, which keeps radio overhead bounded
    while retaining a wide authentication margin for this application.
    """

    AUTH_COMMAND = LC3_AUTH_COMMAND
    AUTH_VERSION = LC3_AUTH_VERSION
    AUTH_DOMAIN = LC3_AUTH_DOMAIN
    ENV_PREFIX = "GUTOCHAT_LC3_AUTH"
    REPLAY_NAMESPACE = ""

    def __init__(
        self,
        key: bytes | None,
        *,
        key_id: str = "default",
        send_authenticated: bool = False,
        require_authenticated: bool = False,
        max_skew_seconds: int = LC3_AUTH_MAX_SKEW_SECONDS,
        replay_store: ReplayStore | None = None,
    ) -> None:
        if key is None and (send_authenticated or require_authenticated):
            raise ValueError(
                "LC3-auth kan ikke sende eller kreves uten GUTOCHAT_LC3_AUTH_KEY"
            )
        if key is not None and len(key) < 16:
            raise ValueError("LC3-autentiseringsnøkkelen må være minst 128 bit")
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,16}", key_id) is None:
            raise ValueError("Ugyldig LC3 key_id")
        self.key = key
        self.key_id = key_id
        self.send_authenticated = bool(send_authenticated and key)
        self.require_authenticated = bool(require_authenticated and key)
        self.max_skew_seconds = max(30, int(max_skew_seconds))
        self.replay_store = replay_store
        self._seen: dict[tuple[str, str], int] = {}

    @staticmethod
    def _env_true(value: str | None) -> bool:
        return str(value or "").strip().casefold() in {"1", "true", "yes", "on"}

    @staticmethod
    def _load_file_backed_key(path_text: str) -> bytes:
        """Load one production LC3 credential without following symlinks.

        The accepted on-disk representation is intentionally narrow:
        ``hex:`` followed by exactly 64 hexadecimal characters and an
        optional single newline.  The file must belong to the effective user,
        be a regular file, be owner-readable, have no owner execute bit and
        expose no group/world permissions.
        """
        import stat

        path = os.path.expanduser(str(path_text).strip())
        if not path:
            raise ValueError("Tom GUTOCHAT_LC3_AUTH_KEY_FILE")

        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise ValueError("LC3 credential-fil kunne ikke åpnes sikkert") from exc

        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("LC3 credential må være en regulær fil")
            if info.st_uid != os.geteuid():
                raise ValueError("LC3 credential har feil eier")

            mode = stat.S_IMODE(info.st_mode)
            if not (mode & stat.S_IRUSR):
                raise ValueError("LC3 credential mangler eier-lesetilgang")
            if mode & stat.S_IXUSR:
                raise ValueError("LC3 credential skal ikke være kjørbar")
            if mode & 0o077:
                raise ValueError("LC3 credential har gruppe-/verdensrettigheter")

            # Exact production format is 68 bytes, or 69 with one LF.
            if info.st_size not in (68, 69):
                raise ValueError("LC3 credential har ugyldig størrelse")
            chunks: list[bytes] = []
            remaining = int(info.st_size)
            while remaining:
                part = os.read(fd, remaining)
                if not part:
                    raise ValueError("LC3 credential ble avkortet under lesing")
                chunks.append(part)
                remaining -= len(part)
            raw = b"".join(chunks)
            if os.read(fd, 1):
                raise ValueError("LC3 credential overskrider tillatt størrelse")
        finally:
            os.close(fd)

        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("LC3 credential må være ASCII") from exc
        if text.endswith("\n"):
            text = text[:-1]
        if re.fullmatch(r"hex:[0-9A-Fa-f]{64}", text) is None:
            raise ValueError("LC3 credential har ugyldig produksjonsformat")
        return bytes.fromhex(text[4:])

    @classmethod
    def from_environment(
        cls, replay_store: ReplayStore | None = None
    ) -> "ControlAuthenticator":
        prefix = cls.ENV_PREFIX
        value = os.environ.get(f"{prefix}_KEY", "").strip()
        key_file = os.environ.get(f"{prefix}_KEY_FILE", "").strip()
        if value and key_file:
            raise ValueError(f"{prefix}_KEY og {prefix}_KEY_FILE kan ikke brukes samtidig")

        key: bytes | None = None
        if key_file:
            key = cls._load_file_backed_key(key_file)
        elif value:
            if value.startswith("hex:"):
                try:
                    key = bytes.fromhex(value[4:])
                except ValueError as exc:
                    raise ValueError(f"Ugyldig hex-format i {prefix}_KEY") from exc
            else:
                key = value.encode("utf-8")
        return cls(
            key,
            key_id=os.environ.get(f"{prefix}_KEY_ID", "default").strip() or "default",
            send_authenticated=cls._env_true(os.environ.get(f"{prefix}_SEND")),
            require_authenticated=cls._env_true(os.environ.get(f"{prefix}_REQUIRED")),
            max_skew_seconds=int(os.environ.get(f"{prefix}_MAX_SKEW_SECONDS", str(LC3_AUTH_MAX_SKEW_SECONDS))),
            replay_store=replay_store,
        )

    @property
    def enabled(self) -> bool:
        return self.key is not None

    @classmethod
    def is_authenticated_frame(cls, text: str) -> bool:
        return text.startswith(f"{LC3_PREFIX}{cls.AUTH_COMMAND}|")

    def _mac_input(self, key_id: str, timestamp: int, nonce: str, text: str) -> bytes:
        return (
            self.AUTH_DOMAIN
            + key_id.encode("ascii")
            + b"\0"
            + str(int(timestamp)).encode("ascii")
            + b"\0"
            + nonce.encode("ascii")
            + b"\0"
            + text.encode("utf-8")
        )

    def wrap(
        self,
        text: str,
        *,
        timestamp: int | None = None,
        nonce: str | None = None,
    ) -> str:
        if not self.enabled:
            raise ValueError("LC3-autentisering er ikke konfigurert")
        if not text.startswith(LC3_PREFIX):
            raise ValueError("Bare LC3-kontrollrammer kan autentiseres")
        stamp = int(time.time()) if timestamp is None else int(timestamp)
        nonce_value = nonce or secrets.token_hex(8)
        if re.fullmatch(r"[0-9a-f]{16}", nonce_value) is None:
            raise ValueError("LC3 auth nonce må være 64-bit hex")
        assert self.key is not None
        digest = hmac.new(
            self.key,
            self._mac_input(self.key_id, stamp, nonce_value, text),
            hashlib.sha256,
        ).hexdigest()[:32]
        return _lc3(
            self.AUTH_COMMAND,
            self.AUTH_VERSION,
            self.key_id,
            stamp,
            nonce_value,
            digest,
            text,
        )

    def unwrap(
        self,
        text: str,
        *,
        check_freshness: bool = False,
        check_replay: bool = False,
        now: int | None = None,
    ) -> AuthenticatedControl:
        if not self.enabled:
            raise ValueError("LC3-autentisering er ikke konfigurert")
        fields = split_escaped(text[len(LC3_PREFIX) :])
        if len(fields) != 7 or fields[0] != self.AUTH_COMMAND:
            raise ValueError("Rammen er ikke en LC3-auth-konvolutt")
        version, key_id, timestamp_text, nonce, supplied_mac, inner = fields[1:]
        if version != self.AUTH_VERSION:
            raise ValueError("Ukjent LC3-auth-versjon")
        if key_id != self.key_id:
            raise ValueError("Ukjent LC3 auth key_id")
        if re.fullmatch(r"[0-9a-f]{16}", nonce) is None:
            raise ValueError("Ugyldig LC3 auth nonce")
        if re.fullmatch(r"[0-9a-f]{32}", supplied_mac) is None:
            raise ValueError("Ugyldig LC3 auth MAC")
        if not inner.startswith(LC3_PREFIX):
            raise ValueError("LC3-auth-konvolutten mangler indre LC3-ramme")
        try:
            stamp = int(timestamp_text)
        except ValueError as exc:
            raise ValueError("Ugyldig LC3 auth timestamp") from exc
        assert self.key is not None
        expected = hmac.new(
            self.key,
            self._mac_input(key_id, stamp, nonce, inner),
            hashlib.sha256,
        ).hexdigest()[:32]
        if not hmac.compare_digest(supplied_mac, expected):
            raise ValueError("LC3-autentisering feilet")

        current = int(time.time()) if now is None else int(now)
        if check_freshness and abs(current - stamp) > self.max_skew_seconds:
            raise ValueError("LC3-auth-rammen er utenfor tidsvinduet")
        if check_replay:
            if self.replay_store is not None:
                replay_key_id = f"{self.REPLAY_NAMESPACE}{key_id}"
                accepted = self.replay_store.check_and_remember(
                    replay_key_id,
                    nonce,
                    stamp,
                    current_epoch=current,
                    max_skew_seconds=self.max_skew_seconds,
                )
                if not accepted:
                    raise ValueError("LC3-auth replay avvist")
            else:
                cutoff = current - self.max_skew_seconds
                for cache_key, seen_stamp in list(self._seen.items()):
                    if seen_stamp < cutoff:
                        self._seen.pop(cache_key, None)
                cache_key = (f"{self.REPLAY_NAMESPACE}{key_id}", nonce)
                if cache_key in self._seen:
                    raise ValueError("LC3-auth replay avvist")
                self._seen[cache_key] = stamp
        return AuthenticatedControl(inner, key_id, stamp, nonce)

    def encode_outbound(self, text: str) -> str:
        if self.send_authenticated:
            return self.wrap(text)
        return text

    def decode_inbound(
        self,
        text: str,
        *,
        live: bool,
    ) -> tuple[str, AuthenticatedControl | None]:
        if self.is_authenticated_frame(text):
            verified = self.unwrap(
                text,
                check_freshness=live,
                check_replay=live,
            )
            return verified.text, verified
        if live and self.require_authenticated and text.startswith(LC3_PREFIX):
            raise ValueError("Usignert LC3-kontrollramme avvist")
        return text, None


class StatusAuthenticator(ControlAuthenticator):
    """HMAC scope dedicated to read-only Field→Base status exchange."""

    AUTH_COMMAND = LC3_STATUS_AUTH_COMMAND
    AUTH_VERSION = LC3_STATUS_AUTH_VERSION
    AUTH_DOMAIN = LC3_STATUS_AUTH_DOMAIN
    ENV_PREFIX = "GUTOCHAT_LC3_STATUS_AUTH"
    REPLAY_NAMESPACE = "status:"


def _route_encode(route: str) -> str:
    return _ROUTE_TO_WIRE.get(route, route)


def _route_decode(route: str) -> str:
    return _WIRE_TO_ROUTE.get(route, route)


def _destination_encode(destination: str | int) -> str:
    if destination in {"^all", "4294967295", 0xFFFFFFFF, "broadcast"}:
        return "*"
    value = str(destination)
    if value.startswith("!") and _NODE_ID_RE.fullmatch(value[1:]):
        return value[1:].lower()
    return value


def _destination_decode(destination: str, route: str) -> str:
    if destination == "*":
        return "^all"
    if route.startswith("mesh") and _NODE_ID_RE.fullmatch(destination):
        return "!" + destination.lower()
    return destination


def is_control(text: str) -> bool:
    return text.startswith((LC2_PREFIX, LC3_PREFIX))


def is_fragment(text: str) -> bool:
    return text.startswith(f"{LC3_PREFIX}F|")


def frame_bytes(value: str) -> int:
    """Return the exact UTF-8 size of a control frame."""
    return len(value.encode("utf-8"))


def encode_send(
    request_id: str,
    route: str,
    destination: str | int,
    channel: int,
    text: str,
    *,
    legacy: bool = False,
) -> str:
    if legacy:
        return (
            f"{LC2_PREFIX}SEND|{request_id}|{route}|{destination}|"
            f"{int(channel)}|{_b64_encode(text)}"
        )
    return _lc3(
        "S",
        request_id,
        _route_encode(route),
        _destination_encode(destination),
        int(channel),
        text,
    )


def encode_node_request(
    request_id: str, route: str, since_revision: int = 0, *, legacy: bool = False
) -> str:
    if legacy:
        return f"{LC2_PREFIX}NREQ|{request_id}|{route}|{max(0, int(since_revision))}"
    return _lc3("NR", request_id, _route_encode(route), max(0, int(since_revision)))


def encode_info_request(request_id: str, route: str, *, legacy: bool = False) -> str:
    if legacy:
        return f"{LC2_PREFIX}IREQ|{request_id}|{route}"
    return _lc3("IR", request_id, _route_encode(route))


def encode_node(
    request_id: str,
    route: str,
    num: int,
    node_id: str,
    short_name: str,
    long_name: str,
    *,
    revision: int = 0,
    last_heard: int | None = None,
    snr: float | None = None,
    max_bytes: int = 185,
    legacy: bool = False,
) -> str:
    """Encode one node change.

    LC3 keeps the complete display name and lets the transport fragment the
    frame.  LC2 must fit one old frame, so only the LC2 fallback truncates the
    long display name.
    """
    last_value = "" if last_heard is None else str(int(last_heard))
    snr_value = "" if snr is None else f"{float(snr):.2f}".rstrip("0").rstrip(".")
    if not legacy:
        compact_id = node_id[1:] if node_id.startswith("!") else node_id
        return _lc3(
            "N",
            request_id,
            _route_encode(route),
            int(revision),
            compact_id,
            last_value,
            snr_value,
            short_name,
            long_name,
        )

    long_value = long_name
    while True:
        value = (
            f"{LC2_PREFIX}NODE|{request_id}|{route}|{int(revision)}|"
            f"{int(num)}|{node_id}|{last_value}|{snr_value}|"
            f"{_b64_encode(short_name)}|{_b64_encode(long_value)}"
        )
        if frame_bytes(value) <= max_bytes or not long_value:
            return value
        long_value = long_value[:-1]


def encode_nodes_done(
    request_id: str,
    route: str,
    sent_count: int,
    *,
    total_count: int | None = None,
    revision: int = 0,
    legacy: bool = False,
) -> str:
    total = int(sent_count if total_count is None else total_count)
    if legacy:
        return (
            f"{LC2_PREFIX}NDONE|{request_id}|{route}|{int(sent_count)}|"
            f"{total}|{int(revision)}"
        )
    return _lc3(
        "ND",
        request_id,
        _route_encode(route),
        int(sent_count),
        total,
        int(revision),
    )


def encode_gateway_queued(
    request_id: str,
    route: str,
    state: str,
    attempts: int,
    next_attempt_epoch: float | None = None,
    detail: str = "",
) -> str:
    next_value = "" if next_attempt_epoch in (None, 0) else str(int(next_attempt_epoch))
    return _lc3(
        "Q",
        request_id,
        _route_encode(route),
        state,
        int(attempts),
        next_value,
        detail,
    )


def encode_gateway_ack(
    request_id: str,
    route: str,
    packet_id: str,
    destination: str | int,
    *,
    legacy: bool = False,
) -> str:
    if legacy:
        return f"{LC2_PREFIX}GWACK|{request_id}|{route}|{packet_id}|{destination}"
    return _lc3(
        "A",
        request_id,
        _route_encode(route),
        packet_id,
        _destination_encode(destination),
    )


def encode_gateway_delivered(
    request_id: str,
    route: str,
    packet_id: str,
    destination: str | int,
    *,
    legacy: bool = False,
) -> str:
    if legacy:
        return f"{LC2_PREFIX}GWDEL|{request_id}|{route}|{packet_id}|{destination}"
    return _lc3(
        "D",
        request_id,
        _route_encode(route),
        packet_id,
        _destination_encode(destination),
    )


def encode_gateway_nak(
    request_id: str,
    route: str,
    packet_id: str,
    destination: str | int,
    reason: str,
    *,
    legacy: bool = False,
) -> str:
    if legacy:
        return (
            f"{LC2_PREFIX}GWNAK|{request_id}|{route}|{packet_id}|{destination}|"
            f"{_b64_encode(reason[:100])}"
        )
    return _lc3(
        "X",
        request_id,
        _route_encode(route),
        packet_id,
        _destination_encode(destination),
        reason[:160],
    )


def encode_gateway_error(
    request_id: str, route: str, error: str, *, legacy: bool = False
) -> str:
    if legacy:
        return f"{LC2_PREFIX}GWERR|{request_id}|{route}|{_b64_encode(error[:90])}"
    return _lc3("E", request_id, _route_encode(route), error[:180])


def encode_info(
    request_id: str,
    route: str,
    version: str,
    network_name: str,
    online: bool,
    node_count: int,
    *,
    legacy: bool = False,
) -> str:
    if legacy:
        return (
            f"{LC2_PREFIX}INFO|{request_id}|{route}|{version}|"
            f"{1 if online else 0}|{int(node_count)}|{_b64_encode(network_name)}"
        )
    return _lc3(
        "I",
        request_id,
        _route_encode(route),
        version,
        1 if online else 0,
        int(node_count),
        network_name,
    )


def encode_gateway_identity(
    request_id: str,
    route: str,
    node_id: str,
    long_name: str,
    short_name: str,
) -> str:
    """Advertise the gateway radio's own Meshtastic identity.

    This is a backward-compatible LC3 extension. Older LoRa Chat clients
    ignore the unknown control frame, while beta1a clients use it to mark the
    gateway node and refresh its names independently of incremental NodeDB
    deltas.
    """
    compact_id = node_id[1:] if node_id.startswith("!") else node_id
    return _lc3(
        "GI",
        request_id,
        _route_encode(route),
        compact_id,
        short_name,
        long_name,
    )


def encode_mesh_in(
    route: str,
    source_id: str,
    source_label: str,
    destination: str | int,
    channel: int,
    text: str,
    max_bytes: int = 185,
    *,
    message_uid: str = "",
    legacy: bool = False,
) -> str | None:
    """Encode an inbound Meshtastic message.

    LC3 keeps the complete message and relies on limited fragmentation.  LC2
    retains the beta3 truncation behavior for compatibility with old Mobile.
    """
    if not legacy:
        compact_source = source_id[1:] if source_id.startswith("!") else source_id
        return _lc3(
            "M",
            _route_encode(route),
            message_uid,
            compact_source,
            _destination_encode(destination),
            int(channel),
            source_label,
            text,
        )

    text_value = text
    truncated = False
    while True:
        value = (
            f"{LC2_PREFIX}MESHIN|{route}|{source_id}|"
            f"{_b64_encode(source_label)}|{destination}|{int(channel)}|"
            f"{1 if truncated else 0}|{_b64_encode(text_value)}"
        )
        if frame_bytes(value) <= max_bytes:
            return value
        if not text_value:
            return None
        text_value = text_value[:-1]
        truncated = True


def encode_position_request(
    request_id: str, route: str, since_revision: int
) -> str:
    return _lc3(
        "PR",
        request_id,
        _route_encode(route),
        max(0, int(since_revision)),
    )


def encode_position_sync(
    request_id: str,
    route: str,
    revision: int,
    payload: dict[str, Any],
) -> str:
    compact = json.dumps(
        compact_position_payload(payload),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    compressed = _b64_bytes_encode(zlib.compress(compact, level=9))
    return _lc3(
        "P",
        request_id,
        _route_encode(route),
        int(revision),
        compressed,
    )


def encode_positions_done(
    request_id: str,
    route: str,
    revision: int,
    count: int,
) -> str:
    return _lc3(
        "PD",
        request_id,
        _route_encode(route),
        int(revision),
        int(count),
    )


def encode_position_history_request(
    request_id: str,
    route: str,
    since_sequence: int,
    limit: int = 10,
) -> str:
    """Encode a bounded position-history request."""
    return _lc3(
        "HR",
        request_id,
        _route_encode(route),
        max(0, int(since_sequence)),
        max(1, min(int(limit), 50)),
    )


def encode_position_history_sync(
    request_id: str,
    route: str,
    sequence: int,
    payload: dict[str, Any],
) -> str:
    """Encode one compressed position-history point."""
    compact = json.dumps(
        compact_position_payload(payload),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    compressed = _b64_bytes_encode(zlib.compress(compact, level=9))
    return _lc3(
        "H",
        request_id,
        _route_encode(route),
        int(sequence),
        compressed,
    )


def encode_position_history_done(
    request_id: str,
    route: str,
    sequence: int,
    count: int,
    more: bool,
) -> str:
    """Encode the end marker for one history batch."""
    return _lc3(
        "HD",
        request_id,
        _route_encode(route),
        int(sequence),
        int(count),
        1 if more else 0,
    )


def encode_message_request(
    request_id: str, route: str, since_sequence: int, limit: int = 10
) -> str:
    return _lc3(
        "MR",
        request_id,
        _route_encode(route),
        max(0, int(since_sequence)),
        max(1, min(int(limit), 50)),
    )


def encode_message_sync(
    request_id: str,
    route: str,
    sequence: int,
    event_type: str,
    payload: dict[str, Any],
) -> str:
    compact = json.dumps(
        compact_message_payload(payload),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    compressed = _b64_bytes_encode(zlib.compress(compact, level=9))
    return _lc3(
        "MS",
        request_id,
        _route_encode(route),
        int(sequence),
        event_type,
        compressed,
    )


def encode_message_done(
    request_id: str,
    route: str,
    sequence: int,
    count: int,
    more: bool,
) -> str:
    return _lc3(
        "MD",
        request_id,
        _route_encode(route),
        int(sequence),
        int(count),
        1 if more else 0,
    )



def encode_aprs_history_request(
    request_id: str, route: str, since_sequence: int, limit: int = 10,
    *, snapshot_baseline: int = 0, snapshot_after: int = 0,
) -> str:
    """Request one bounded APRS batch. Cursor zero invokes stable latest bootstrap."""
    since = max(0, int(since_sequence))
    base = max(0, int(snapshot_baseline))
    after = max(0, int(snapshot_after))
    if since == 0 or base or after:
        return _lc3(
            "AR", request_id, _route_encode(route), since,
            max(1, min(int(limit), 50)), base, after,
        )
    return _lc3(
        "AR", request_id, _route_encode(route), since,
        max(1, min(int(limit), 50)),
    )


def encode_aprs_history_sync(
    request_id: str,
    route: str,
    sequence: int,
    payload: dict[str, Any],
) -> str:
    """Encode one bounded compact presentation-only APRS observation."""
    wire_payload: Any
    if {"station_id", "latitude", "longitude", "received_epoch"}.issubset(payload):
        wire_payload = compact_aprs_payload(payload)
    else:
        wire_payload = payload
    compact = json.dumps(
        wire_payload,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    compressed = _b64_bytes_encode(zlib.compress(compact, level=9))
    return _lc3("AS", request_id, _route_encode(route), int(sequence), compressed)


def encode_aprs_history_done(
    request_id: str,
    route: str,
    sequence: int,
    count: int,
    more: bool,
    *,
    resync_required: bool = False,
    snapshot_baseline: int = 0,
    snapshot_after: int = 0,
) -> str:
    base = max(0, int(snapshot_baseline))
    after = max(0, int(snapshot_after))
    if base or after:
        return _lc3(
            "AD", request_id, _route_encode(route), int(sequence), int(count),
            1 if more else 0, 1 if resync_required else 0, base, after,
        )
    return _lc3(
        "AD", request_id, _route_encode(route), int(sequence), int(count),
        1 if more else 0, 1 if resync_required else 0,
    )


def encode_base_status_request(request_id: str, route: str, resource: str) -> str:
    """Request authenticated authoritative Base state for one allowlisted resource."""
    return _lc3("BR", request_id, _route_encode(route), str(resource).upper())


def encode_base_status_result(
    request_id: str,
    route: str,
    resource: str,
    state: str,
    verified: bool,
    reason_code: str = "",
) -> str:
    return _lc3(
        "BV",
        request_id,
        _route_encode(route),
        str(resource).upper(),
        str(state).upper(),
        1 if verified else 0,
        str(reason_code)[:120],
    )


def encode_base_control_request(
    request_id: str,
    route: str,
    resource: str,
    expected_state: str,
    target_state: str,
) -> str:
    """Encode one fail-closed Field→Base privileged transition request."""
    return _lc3(
        "CR",
        request_id,
        _route_encode(route),
        str(resource).upper(),
        str(expected_state).upper(),
        str(target_state).upper(),
    )


def encode_base_control_result(
    request_id: str,
    route: str,
    resource: str,
    source_state: str,
    target_state: str,
    state: str,
    ok: bool,
    verified: bool,
    reason_code: str,
) -> str:
    return _lc3(
        "CV",
        request_id,
        _route_encode(route),
        str(resource).upper(),
        str(source_state).upper(),
        str(target_state).upper(),
        str(state).upper(),
        1 if ok else 0,
        1 if verified else 0,
        str(reason_code)[:120],
    )

def fragment_frame(
    frame: str,
    *,
    max_bytes: int = 190,
    max_fragments: int = MAX_FRAGMENTS,
    transfer_id: str | None = None,
) -> list[str]:
    """Return one frame or a CRC-protected LC3 fragment sequence.

    Fragments use the same lightweight escaping as other LC3 fields rather
    than base64-encoding the complete frame.  This avoids double base64 for
    compressed sync events and provides roughly 600 logical bytes in four
    190-byte radio packets.
    """
    if frame_bytes(frame) <= max_bytes:
        return [frame]
    if not frame.startswith(LC3_PREFIX):
        raise ValueError("Bare LC3-rammer kan fragmenteres")
    raw = frame.encode("utf-8")
    transfer = (transfer_id or uuid.uuid4().hex[:8])[:12]
    crc = f"{zlib.crc32(raw) & 0xFFFFFFFF:08x}"
    chunks: list[str] = []
    current = ""
    for char in frame:
        candidate = current + char
        probe = _lc3("F", transfer, max_fragments, max_fragments, crc, candidate)
        if frame_bytes(probe) <= max_bytes:
            current = candidate
            continue
        if not current:
            raise ValueError("Ett UTF-8-tegn får ikke plass i et LC3-fragment")
        chunks.append(current)
        current = char
        if len(chunks) >= max_fragments:
            raise ValueError(
                f"Kontrollmeldingen krever mer enn {max_fragments} fragmenter "
                f"med grense {max_bytes} byte"
            )
    if current:
        chunks.append(current)
    if len(chunks) > max_fragments:
        raise ValueError(
            f"Kontrollmeldingen krever mer enn {max_fragments} fragmenter "
            f"med grense {max_bytes} byte"
        )
    frames = [
        _lc3("F", transfer, index + 1, len(chunks), crc, chunk)
        for index, chunk in enumerate(chunks)
    ]
    if not all(frame_bytes(item) <= max_bytes for item in frames):
        raise ValueError("Internt fragmenteringsavvik")
    return frames


@dataclass
class _FragmentSet:
    count: int
    crc: str
    created: float
    parts: dict[int, str] = field(default_factory=dict)


class FragmentAssembler:
    """In-memory, duplicate-tolerant assembler for limited LC3 fragments."""

    def __init__(self, *, ttl_seconds: float = 300.0, max_fragments: int = MAX_FRAGMENTS):
        self.ttl_seconds = max(5.0, float(ttl_seconds))
        self.max_fragments = max(1, int(max_fragments))
        self._sets: dict[tuple[str, str], _FragmentSet] = {}

    def cleanup(self) -> None:
        cutoff = time.monotonic() - self.ttl_seconds
        for key, value in list(self._sets.items()):
            if value.created < cutoff:
                self._sets.pop(key, None)

    def add(self, control: dict[str, Any], *, source_key: str = "") -> str | None:
        if control.get("command") != "FRAGMENT":
            raise ValueError("Kontrollen er ikke et fragment")
        transfer_id = str(control["transfer_id"])
        index = int(control["index"])
        count = int(control["count"])
        crc = str(control["crc"]).lower()
        payload = control.get("payload_text")
        if not isinstance(payload, str):
            raise ValueError("Fragmentet mangler tekstnyttelast")
        if count < 2 or count > self.max_fragments or not 1 <= index <= count:
            raise ValueError("Ugyldig fragmentnummer eller antall")
        self.cleanup()
        key = (source_key, transfer_id)
        current = self._sets.get(key)
        if current is None:
            current = _FragmentSet(count=count, crc=crc, created=time.monotonic())
            self._sets[key] = current
        elif current.count != count or current.crc != crc:
            self._sets.pop(key, None)
            raise ValueError("Fragmentserien endret antall eller kontrollsum")
        current.parts[index] = payload
        if len(current.parts) != count:
            return None
        complete = "".join(current.parts[position] for position in range(1, count + 1))
        self._sets.pop(key, None)
        raw = complete.encode("utf-8")
        actual = f"{zlib.crc32(raw) & 0xFFFFFFFF:08x}"
        if actual != crc:
            raise ValueError("CRC-feil i sammensatt LC3-kontrollmelding")
        return complete


def parse_routing_result(packet: dict[str, Any]) -> tuple[bool, str]:
    """Interpret a Meshtastic ACK/NAK callback packet."""
    decoded = packet.get("decoded", {}) if isinstance(packet, dict) else {}
    routing = decoded.get("routing", {}) if isinstance(decoded, dict) else {}
    if not isinstance(routing, dict):
        return False, "UKJENT_SVAR"
    reason = routing.get("errorReason", "NONE")
    if reason in (None, "", 0, "NONE"):
        return True, "NONE"
    return False, str(reason)


def _parse_lc3(text: str) -> dict[str, Any] | None:
    fields = split_escaped(text[len(LC3_PREFIX) :])
    if not fields:
        return None
    command = fields[0]
    try:
        if command == "S" and len(fields) == 6:
            route = _route_decode(fields[2])
            return {
                "command": "SEND",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": route,
                "destination": _destination_decode(fields[3], route),
                "channel": int(fields[4]),
                "text": fields[5],
            }
        if command == "NR" and len(fields) == 4:
            return {
                "command": "NREQ",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "since_revision": int(fields[3]),
                "legacy": False,
            }
        if command == "IR" and len(fields) == 3:
            return {
                "command": "IREQ",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
            }
        if command == "N" and len(fields) == 9:
            route = _route_decode(fields[2])
            node_id = fields[4]
            if _NODE_ID_RE.fullmatch(node_id):
                node_id = "!" + node_id.lower()
            return {
                "command": "NODE",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": route,
                "revision": int(fields[3]),
                "num": destination_to_num(node_id),
                "id": node_id,
                "last_heard": int(fields[5]) if fields[5] else None,
                "snr": float(fields[6]) if fields[6] else None,
                "short_name": fields[7],
                "long_name": fields[8],
            }
        if command == "ND" and len(fields) == 6:
            return {
                "command": "NDONE",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "sent_count": int(fields[3]),
                "count": int(fields[4]),
                "total_count": int(fields[4]),
                "revision": int(fields[5]),
            }
        if command in {"A", "D"} and len(fields) == 5:
            route = _route_decode(fields[2])
            return {
                "command": "GWACK" if command == "A" else "GWDEL",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": route,
                "packet_id": fields[3],
                "destination": _destination_decode(fields[4], route),
            }
        if command == "Q" and len(fields) == 7:
            return {
                "command": "GWQUEUED",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "state": fields[3],
                "attempts": int(fields[4]),
                "next_attempt_epoch": int(fields[5]) if fields[5] else None,
                "detail": fields[6],
            }
        if command == "X" and len(fields) == 6:
            route = _route_decode(fields[2])
            return {
                "command": "GWNAK",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": route,
                "packet_id": fields[3],
                "destination": _destination_decode(fields[4], route),
                "reason": fields[5],
            }
        if command == "E" and len(fields) == 4:
            return {
                "command": "GWERR",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "error": fields[3],
            }
        if command == "I" and len(fields) == 7:
            return {
                "command": "INFO",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "version": fields[3],
                "online": fields[4] == "1",
                "node_count": int(fields[5]),
                "network_name": fields[6],
            }
        if command == "GI" and len(fields) == 6:
            route = _route_decode(fields[2])
            node_id = fields[3]
            if _NODE_ID_RE.fullmatch(node_id):
                node_id = "!" + node_id.lower()
            return {
                "command": "GWIDENT",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": route,
                "id": node_id,
                "num": destination_to_num(node_id),
                "short_name": fields[4],
                "long_name": fields[5],
            }
        if command == "M" and len(fields) == 8:
            route = _route_decode(fields[1])
            source_id = fields[3]
            if _NODE_ID_RE.fullmatch(source_id):
                source_id = "!" + source_id.lower()
            return {
                "command": "MESHIN",
                "protocol": "LC3",
                "route": route,
                "message_uid": fields[2],
                "source_id": source_id,
                "source_label": fields[6],
                "destination": _destination_decode(fields[4], route),
                "channel": int(fields[5]),
                "truncated": False,
                "text": fields[7],
            }
        if command == "PR" and len(fields) == 4:
            return {
                "command": "PREQ",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "since_revision": int(fields[3]),
            }
        if command == "P" and len(fields) == 5:
            compressed = _b64_bytes_decode(fields[4])
            inflater = zlib.decompressobj()
            raw_bytes = inflater.decompress(compressed, 16385)
            if len(raw_bytes) > 16384 or inflater.unconsumed_tail:
                return None
            raw_bytes += inflater.flush()
            if len(raw_bytes) > 16384:
                return None
            payload = json.loads(raw_bytes.decode("utf-8"))
            if not isinstance(payload, dict):
                return None
            return {
                "command": "POS",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "revision": int(fields[3]),
                "payload": expand_position_payload(payload),
            }
        if command == "PD" and len(fields) == 5:
            return {
                "command": "PDONE",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "revision": int(fields[3]),
                "count": int(fields[4]),
            }
        if command == "HR" and len(fields) == 5:
            return {
                "command": "HREQ",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "since_sequence": int(fields[3]),
                "limit": max(1, min(int(fields[4]), 50)),
            }
        if command == "H" and len(fields) == 5:
            compressed = _b64_bytes_decode(fields[4])
            inflater = zlib.decompressobj()
            raw_bytes = inflater.decompress(compressed, 16385)
            if len(raw_bytes) > 16384 or inflater.unconsumed_tail:
                return None
            raw_bytes += inflater.flush()
            if len(raw_bytes) > 16384:
                return None
            payload = json.loads(raw_bytes.decode("utf-8"))
            if not isinstance(payload, dict):
                return None
            return {
                "command": "HSYNC",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "sequence": int(fields[3]),
                "payload": expand_position_payload(payload),
            }
        if command == "HD" and len(fields) == 6:
            return {
                "command": "HDONE",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "sequence": int(fields[3]),
                "count": int(fields[4]),
                "more": fields[5] == "1",
            }
        if command == "MR" and len(fields) == 5:
            return {
                "command": "MREQ",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "since_sequence": int(fields[3]),
                "limit": int(fields[4]),
            }
        if command == "MS" and len(fields) == 6:
            compressed = _b64_bytes_decode(fields[5])
            inflater = zlib.decompressobj()
            raw_bytes = inflater.decompress(compressed, 16385)
            if len(raw_bytes) > 16384 or inflater.unconsumed_tail:
                return None
            raw_bytes += inflater.flush()
            if len(raw_bytes) > 16384:
                return None
            raw_payload = raw_bytes.decode("utf-8")
            payload = json.loads(raw_payload)
            if not isinstance(payload, dict):
                return None
            return {
                "command": "MSYNC",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "sequence": int(fields[3]),
                "event_type": fields[4],
                "payload": expand_message_payload(payload),
            }
        if command == "MD" and len(fields) == 6:
            return {
                "command": "MDONE",
                "protocol": "LC3",
                "request_id": fields[1],
                "route": _route_decode(fields[2]),
                "sequence": int(fields[3]),
                "count": int(fields[4]),
                "more": fields[5] == "1",
            }
        if command == "AR" and len(fields) in {5, 7}:
            result = {
                "command": "AREQ", "protocol": "LC3",
                "request_id": fields[1], "route": _route_decode(fields[2]),
                "since_sequence": int(fields[3]),
                "limit": max(1, min(int(fields[4]), 50)),
            }
            if len(fields) == 7:
                result["snapshot_baseline"] = max(0, int(fields[5]))
                result["snapshot_after"] = max(0, int(fields[6]))
            return result
        if command == "AS" and len(fields) == 5:
            compressed = _b64_bytes_decode(fields[4])
            inflater = zlib.decompressobj()
            raw_bytes = inflater.decompress(compressed, 16385)
            if len(raw_bytes) > 16384 or inflater.unconsumed_tail:
                return None
            raw_bytes += inflater.flush()
            if len(raw_bytes) > 16384:
                return None
            payload = expand_aprs_payload(json.loads(raw_bytes.decode("utf-8")))
            return {
                "command": "ASYNC", "protocol": "LC3",
                "request_id": fields[1], "route": _route_decode(fields[2]),
                "sequence": int(fields[3]), "payload": payload,
            }
        if command == "AD" and len(fields) in {7, 9}:
            result = {
                "command": "ADONE", "protocol": "LC3",
                "request_id": fields[1], "route": _route_decode(fields[2]),
                "sequence": int(fields[3]), "count": int(fields[4]),
                "more": fields[5] == "1", "resync_required": fields[6] == "1",
                "snapshot_baseline": 0, "snapshot_after": 0,
            }
            if len(fields) == 9:
                result["snapshot_baseline"] = max(0, int(fields[7]))
                result["snapshot_after"] = max(0, int(fields[8]))
            return result
        if command == "BR" and len(fields) == 4:
            return {
                "command": "BASE_STATUS_REQ", "protocol": "LC3",
                "request_id": fields[1], "route": _route_decode(fields[2]),
                "resource": fields[3].upper(),
            }
        if command == "BV" and len(fields) == 7:
            return {
                "command": "BASE_STATUS", "protocol": "LC3",
                "request_id": fields[1], "route": _route_decode(fields[2]),
                "resource": fields[3].upper(), "state": fields[4].upper(),
                "verified": fields[5] == "1", "reason_code": fields[6],
            }
        if command == "CR" and len(fields) == 6:
            return {
                "command": "BASE_CONTROL_REQ", "protocol": "LC3",
                "request_id": fields[1], "route": _route_decode(fields[2]),
                "resource": fields[3].upper(),
                "expected_state": fields[4].upper(), "target_state": fields[5].upper(),
            }
        if command == "CV" and len(fields) == 10:
            return {
                "command": "BASE_CONTROL_RESULT", "protocol": "LC3",
                "request_id": fields[1], "route": _route_decode(fields[2]),
                "resource": fields[3].upper(), "source_state": fields[4].upper(),
                "target_state": fields[5].upper(), "state": fields[6].upper(),
                "ok": fields[7] == "1", "verified": fields[8] == "1",
                "reason_code": fields[9],
            }
        if command == "F" and len(fields) == 6:
            transfer_id = fields[1]
            crc = fields[4].lower()
            if (
                re.fullmatch(r"[0-9a-fA-F]{1,12}", transfer_id) is None
                or re.fullmatch(r"[0-9a-f]{8}", crc) is None
            ):
                return None
            return {
                "command": "FRAGMENT",
                "protocol": "LC3",
                "transfer_id": transfer_id,
                "index": int(fields[2]),
                "count": int(fields[3]),
                "crc": crc,
                "payload_text": fields[5],
            }
    except (ValueError, UnicodeError, json.JSONDecodeError, binascii.Error, zlib.error):
        return None
    return None


def _parse_lc2(text: str) -> dict[str, Any] | None:
    parts = text.split("|")
    if len(parts) < 2:
        return None
    command = parts[1]
    try:
        if command == "SEND" and len(parts) == 7:
            return {
                "command": command,
                "protocol": "LC2",
                "request_id": parts[2],
                "route": parts[3],
                "destination": parts[4],
                "channel": int(parts[5]),
                "text": _b64_decode(parts[6]),
            }
        if command == "NREQ" and len(parts) in {4, 5}:
            return {
                "command": command,
                "protocol": "LC2",
                "request_id": parts[2],
                "route": parts[3],
                "since_revision": int(parts[4]) if len(parts) == 5 else 0,
                "legacy": True,
            }
        if command == "IREQ" and len(parts) == 4:
            return {
                "command": command,
                "protocol": "LC2",
                "request_id": parts[2],
                "route": parts[3],
            }
        if command == "NODE" and len(parts) == 8:
            return {
                "command": command,
                "protocol": "LC2",
                "request_id": parts[2],
                "route": parts[3],
                "revision": 0,
                "num": int(parts[4]),
                "id": parts[5],
                "last_heard": None,
                "snr": None,
                "short_name": _b64_decode(parts[6]),
                "long_name": _b64_decode(parts[7]),
            }
        if command == "NODE" and len(parts) == 11:
            return {
                "command": command,
                "protocol": "LC2",
                "request_id": parts[2],
                "route": parts[3],
                "revision": int(parts[4]),
                "num": int(parts[5]),
                "id": parts[6],
                "last_heard": int(parts[7]) if parts[7] else None,
                "snr": float(parts[8]) if parts[8] else None,
                "short_name": _b64_decode(parts[9]),
                "long_name": _b64_decode(parts[10]),
            }
        if command == "NDONE" and len(parts) == 5:
            count = int(parts[4])
            return {
                "command": command,
                "protocol": "LC2",
                "request_id": parts[2],
                "route": parts[3],
                "sent_count": count,
                "count": count,
                "total_count": count,
                "revision": 0,
            }
        if command == "NDONE" and len(parts) == 7:
            return {
                "command": command,
                "protocol": "LC2",
                "request_id": parts[2],
                "route": parts[3],
                "sent_count": int(parts[4]),
                "count": int(parts[5]),
                "total_count": int(parts[5]),
                "revision": int(parts[6]),
            }
        if command in {"GWACK", "GWDEL"} and len(parts) == 6:
            return {
                "command": command,
                "protocol": "LC2",
                "request_id": parts[2],
                "route": parts[3],
                "packet_id": parts[4],
                "destination": parts[5],
            }
        if command == "GWNAK" and len(parts) == 7:
            return {
                "command": command,
                "protocol": "LC2",
                "request_id": parts[2],
                "route": parts[3],
                "packet_id": parts[4],
                "destination": parts[5],
                "reason": _b64_decode(parts[6]),
            }
        if command == "GWERR" and len(parts) == 5:
            return {
                "command": command,
                "protocol": "LC2",
                "request_id": parts[2],
                "route": parts[3],
                "error": _b64_decode(parts[4]),
            }
        if command == "INFO" and len(parts) == 8:
            return {
                "command": command,
                "protocol": "LC2",
                "request_id": parts[2],
                "route": parts[3],
                "version": parts[4],
                "online": parts[5] == "1",
                "node_count": int(parts[6]),
                "network_name": _b64_decode(parts[7]),
            }
        if command == "MESHIN" and len(parts) == 8:
            return {
                "command": command,
                "protocol": "LC2",
                "route": parts[2],
                "source_id": parts[3],
                "source_label": _b64_decode(parts[4]),
                "destination": parts[5],
                "channel": int(parts[6]),
                "truncated": False,
                "text": _b64_decode(parts[7]),
            }
        if command == "MESHIN" and len(parts) == 9:
            return {
                "command": command,
                "protocol": "LC2",
                "route": parts[2],
                "source_id": parts[3],
                "source_label": _b64_decode(parts[4]),
                "destination": parts[5],
                "channel": int(parts[6]),
                "truncated": parts[7] == "1",
                "text": _b64_decode(parts[8]),
            }
    except (ValueError, UnicodeError):
        return None
    return None


def parse_control(text: str) -> dict[str, Any] | None:
    if text.startswith(LC3_PREFIX):
        return _parse_lc3(text)
    if text.startswith(LC2_PREFIX):
        return _parse_lc2(text)
    return None


def canonical_meshtastic_id(
    value: str | int | None, *, node_num: int | None = None
) -> str:
    """Return a canonical ``!xxxxxxxx`` Meshtastic node ID when possible.

    Meshtastic packets normally contain a numeric ``from``/``to`` field and
    may also expose a textual ``fromId``/``toId``.  Some library versions have
    represented the textual value as ``!`` followed by the *decimal* node
    number.  When ``node_num`` is supplied, that ambiguity can be resolved
    safely and the value is rendered as eight-digit hexadecimal.
    """
    numeric: int | None = None
    if node_num is not None:
        numeric = int(node_num)
        if not 0 <= numeric <= 0xFFFFFFFF:
            raise ValueError("Meshtastic-node-ID er utenfor gyldig område")

    text = "" if value is None else str(value).strip().lower()
    bare = text[1:] if text.startswith("!") else text

    if numeric is not None and (not bare or bare == str(numeric)):
        return f"!{numeric:08x}"

    if isinstance(value, int):
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Meshtastic-node-ID er utenfor gyldig område")
        return f"!{value:08x}"

    if text.startswith("!") and _NODE_ID_RE.fullmatch(bare):
        return "!" + bare
    # A bare all-decimal value comes from Meshtastic's numeric packet fields;
    # canonical user-facing node IDs are normally prefixed with !.
    if text.isdecimal():
        decimal = int(text)
        if 0 <= decimal <= 0xFFFFFFFF:
            return f"!{decimal:08x}"
    if _NODE_ID_RE.fullmatch(text):
        return "!" + text
    if text.startswith("!") and bare.isdecimal() and len(bare) != 8:
        decimal = int(bare)
        if 0 <= decimal <= 0xFFFFFFFF:
            return f"!{decimal:08x}"
    if numeric is not None:
        return f"!{numeric:08x}"
    return text


def destination_to_num(value: str | int) -> int:
    if value in {"^all", 0xFFFFFFFF, "4294967295", "broadcast", "*"}:
        return 0xFFFFFFFF
    if isinstance(value, str) and value.startswith("!"):
        return int(value[1:], 16)
    return int(value)


SYNC_CONTROL_COMMANDS = frozenset({
    "NREQ", "IREQ", "NODE", "NDONE", "INFO", "GWIDENT",
    "MREQ", "MSYNC", "MDONE",
    "PREQ", "POS", "PDONE",
    "HREQ", "HSYNC", "HDONE",
    "AREQ", "ASYNC", "ADONE",
})
PRIVILEGED_CONTROL_COMMANDS = frozenset({
    "BASE_STATUS_REQ", "BASE_STATUS", "BASE_CONTROL_REQ", "BASE_CONTROL_RESULT",
})


def control_transport_policy(text: str, destination: int | None = None) -> dict[str, Any]:
    """Return bounded-delivery metadata for transient sync traffic.

    Ordinary chat messages and gateway delivery controls deliberately return
    an empty policy and keep the durable 24-hour outbox behaviour. Node, info
    message-history and position synchronization are replaceable state: stale
    sessions must not occupy the radio indefinitely.
    """
    control = parse_control(text)
    if not control:
        return {}
    command = str(control.get("command", ""))
    if command not in SYNC_CONTROL_COMMANDS and command not in PRIVILEGED_CONTROL_COMMANDS:
        return {}
    route = str(control.get("route", ""))
    request_id = str(control.get("request_id", ""))
    target = "" if destination is None else str(int(destination))

    if command in {"NREQ", "IREQ", "MREQ", "PREQ", "HREQ", "AREQ"}:
        group = f"request:{command}:{target}:{route}"
    elif command in {"NODE", "NDONE"}:
        group = f"response:NODES:{target}:{route}"
    elif command in {"POS", "PDONE"}:
        group = f"response:POSITIONS:{target}:{route}"
    elif command in {"HSYNC", "HDONE"}:
        group = f"response:POSITION_HISTORY:{target}:{route}"
    elif command == "INFO":
        group = f"response:INFO:{target}:{route}"
    elif command == "GWIDENT":
        group = f"response:GWIDENT:{target}:{route}"
    elif command in {"ASYNC", "ADONE"}:
        group = f"response:APRS:{target}:{route}"
    elif command in PRIVILEGED_CONTROL_COMMANDS:
        group = f"privileged:{command}:{target}:{route}:{request_id}"
    else:
        group = f"response:MESSAGES:{target}:{route}"

    privileged = command in PRIVILEGED_CONTROL_COMMANDS
    return {
        "traffic_class": "privileged_control" if privileged else "sync",
        "control_command": command,
        "control_route": route,
        "control_request_id": request_id,
        "control_group": group,
        "replace_other_requests": not privileged,
        "max_attempts": 2 if privileged else 3,
        "ttl_seconds": 60.0 if privileged else 180.0,
    }
