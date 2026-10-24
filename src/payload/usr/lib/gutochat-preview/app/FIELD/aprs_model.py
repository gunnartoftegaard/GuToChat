#!/usr/bin/env python3
"""Normalized APRS data model for read-only GuToMap ingestion."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


SOURCE_TYPES = {
    "fixture",
    "aprs_is",
    "local_rf",
}

TRANSPORT_TYPES = {
    "unknown",
    "vhf_ax25",
    "uhf_ax25",
    "dmr_aprs",
    "lora_aprs",
}

PARSE_STATES = {
    "position",
    "non_position",
    "unsupported_position",
    "invalid",
}


def canonical_station_id(value: str) -> tuple[str, str, int | None]:
    """Return canonical APRS textual station ID, base callsign and AX.25 SSID.

    APRS-IS/TNC2 permits one optional 1-2 character *alphanumeric* suffix.
    Direct AX.25 RF, however, only has the numeric SSID space 0..15.  A1.5b
    therefore preserves the complete APRS-IS textual identity in ``station_id``
    while returning ``ssid`` only when the suffix is an unambiguous canonical
    numeric AX.25 SSID.  For example, ``SM4JAY-D`` remains a distinct station
    ID but has ``ssid is None``; ``LA6UIA-9`` has ``ssid == 9``.
    """
    text = str(value or "").strip().upper()
    if not text or any(char.isspace() for char in text):
        raise ValueError("APRS station ID is empty or contains whitespace")
    if len(text) > 9:
        raise ValueError("APRS station ID exceeds the 9-character TNC2/APRS-IS limit")

    suffix: str | None = None
    if "-" in text:
        if text.count("-") != 1:
            raise ValueError("APRS station ID contains multiple suffix separators")
        callsign, suffix = text.split("-", 1)
        if not 1 <= len(suffix) <= 2 or not suffix.isalnum() or not suffix.isascii():
            raise ValueError("APRS station suffix must be 1..2 ASCII alphanumeric characters")
    else:
        callsign = text

    if not 1 <= len(callsign) <= 6 or not callsign.isalnum() or not callsign.isascii():
        raise ValueError("APRS callsign must contain 1..6 ASCII alphanumeric characters")

    ssid: int | None = None
    if suffix is not None and suffix.isdigit():
        numeric = int(suffix)
        # Keep APRS-IS textual identities such as -01 or -16 distinct from an
        # AX.25 SSID.  Only canonical decimal 0..15 is exposed as ``ssid``.
        if str(numeric) == suffix and 0 <= numeric <= 15:
            ssid = numeric

    station_id = callsign if suffix is None else f"{callsign}-{suffix}"
    return station_id, callsign, ssid


def normalize_source_type(value: str) -> str:
    source_type = str(value or "").strip().lower()
    if source_type not in SOURCE_TYPES:
        raise ValueError(f"Unsupported APRS source type: {source_type!r}")
    return source_type


def normalize_transport(value: str) -> str:
    transport = str(value or "").strip().lower()
    if transport not in TRANSPORT_TYPES:
        raise ValueError(f"Unsupported APRS transport: {transport!r}")
    return transport


def normalize_path(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        token = str(value or "").strip()
        if not token:
            continue
        if len(token) > 32 or any(ord(char) < 32 for char in token):
            raise ValueError("Invalid APRS path component")
        result.append(token)
    if len(result) > 16:
        raise ValueError("APRS path contains too many components")
    return tuple(result)




@dataclass(frozen=True)
class AprsWeather:
    """Normalized weather values attached to an APRS position report."""

    wind_direction_deg: int | None = None
    wind_speed_kmh: float | None = None
    gust_kmh: float | None = None
    temperature_c: float | None = None
    rain_last_hour_mm: float | None = None
    rain_last_24h_mm: float | None = None
    rain_since_midnight_mm: float | None = None
    humidity_percent: int | None = None
    pressure_hpa: float | None = None

    def __post_init__(self) -> None:
        if self.wind_direction_deg is not None and not 0 <= int(self.wind_direction_deg) <= 360:
            raise ValueError("APRS weather wind direction must be in the range 0..360")
        for name in (
            "wind_speed_kmh",
            "gust_kmh",
            "rain_last_hour_mm",
            "rain_last_24h_mm",
            "rain_since_midnight_mm",
            "pressure_hpa",
        ):
            value = getattr(self, name)
            if value is not None and float(value) < 0:
                raise ValueError(f"APRS weather {name} cannot be negative")
        if self.humidity_percent is not None and not 1 <= int(self.humidity_percent) <= 100:
            raise ValueError("APRS weather humidity must be in the range 1..100")


@dataclass(frozen=True)
class AprsPosition:
    """A normalized APRS position independent of its RF/network transport."""

    latitude: float
    longitude: float
    symbol_table: str
    symbol_code: str
    altitude_m: float | None = None
    course_deg: int | None = None
    speed_kmh: float | None = None
    packet_time_raw: str | None = None
    comment: str = ""
    ambiguity_digits: int = 0
    position_format: str = "uncompressed"
    weather: AprsWeather | None = None

    def __post_init__(self) -> None:
        if not -90.0 <= float(self.latitude) <= 90.0:
            raise ValueError("APRS latitude is outside -90..90")
        if not -180.0 <= float(self.longitude) <= 180.0:
            raise ValueError("APRS longitude is outside -180..180")
        if len(self.symbol_table) != 1 or not self.symbol_table.isprintable():
            raise ValueError("APRS symbol table identifier must be one character")
        if len(self.symbol_code) != 1 or not self.symbol_code.isprintable():
            raise ValueError("APRS symbol code must be one character")
        if self.course_deg is not None and not 0 <= int(self.course_deg) <= 360:
            raise ValueError("APRS course must be in the range 0..360")
        if self.speed_kmh is not None and float(self.speed_kmh) < 0:
            raise ValueError("APRS speed cannot be negative")
        if not 0 <= int(self.ambiguity_digits) <= 4:
            raise ValueError("APRS ambiguity digit count must be in the range 0..4")
        if self.position_format not in {"uncompressed", "compressed", "mic_e"}:
            raise ValueError("Unsupported APRS position format")


@dataclass(frozen=True)
class AprsPacket:
    """Normalized APRS packet envelope used by parsers and durable storage."""

    station_id: str
    callsign: str
    ssid: int | None
    destination: str
    path: tuple[str, ...]
    information: str
    data_type: str
    parse_state: str
    source_type: str
    transport: str
    received_at: str
    received_epoch: int
    raw_packet_hash: str
    observation_key: str
    position: AprsPosition | None = None
    source_gateway: str = ""
    parse_reason: str = ""
    messaging_capable: bool | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        station_id, callsign, ssid = canonical_station_id(self.station_id)
        if station_id != self.station_id or callsign != self.callsign or ssid != self.ssid:
            raise ValueError("APRS station identity is not canonical")
        if self.parse_state not in PARSE_STATES:
            raise ValueError(f"Unsupported APRS parse state: {self.parse_state!r}")
        normalize_source_type(self.source_type)
        normalize_transport(self.transport)
        if not self.information:
            raise ValueError("APRS information field cannot be empty")
        if len(self.data_type) != 1:
            raise ValueError("APRS data type identifier must be one character")
        if self.parse_state == "position" and self.position is None:
            raise ValueError("Position parse state requires a normalized position")
        if self.position is not None and self.parse_state != "position":
            raise ValueError("Normalized position requires position parse state")
