#!/usr/bin/env python3
"""Fail-closed read-only APRS position/weather parser."""
from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime
from typing import Any

from aprs_model import (
    AprsPacket,
    AprsPosition,
    AprsWeather,
    canonical_station_id,
    normalize_path,
    normalize_source_type,
    normalize_transport,
)


_TNC2_RE = re.compile(r"^([^>:\s]+)>([^:\s]+):(.+)$")
_ALTITUDE_RE = re.compile(r"/A=(\d{6})(?=$|[^0-9])")
_COURSE_SPEED_RE = re.compile(r"^(\d{3})/(\d{3})(.*)$", re.DOTALL)
_WEATHER_WIND_RE = re.compile(r"^([0-9. V]{3})/([0-9. V]{3})(.*)$", re.DOTALL)
_UNCOMPRESSED_LAT_RE = re.compile(r"^(\d{2})(\d{2})\.(\d{2})([NS])$")
_UNCOMPRESSED_LON_RE = re.compile(r"^(\d{3})(\d{2})\.(\d{2})([EW])$")
_TIMESTAMP_RE = re.compile(r"^\d{6}[z/h]$")

POSITION_DTIS = {"!", "=", "/", "@"}
TIMESTAMPED_DTIS = {"/", "@"}
MESSAGING_DTIS = {"=", "@"}
MIC_E_DTIS = {"`", "'", "\x1c", "\x1d"}

# APRS 1.0.1 Chapter 12 fixed-width weather parameters after the 7-byte
# DIR/SPD extension in complete position weather reports.
_WEATHER_FIELDS: dict[str, tuple[int, str]] = {
    "g": (3, "gust"),
    "t": (3, "temperature"),
    "r": (3, "rain_last_hour"),
    "p": (3, "rain_last_24h"),
    "P": (3, "rain_since_midnight"),
    "h": (2, "humidity"),
    "b": (5, "pressure"),
}


class AprsParseError(ValueError):
    """Raised for structurally invalid APRS input, not unsupported formats."""


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _iso_to_epoch(value: str) -> int:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AprsParseError("received_at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise AprsParseError("received_at must include a timezone offset")
    return int(parsed.timestamp())


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _make_packet(
    *,
    station_id: str,
    callsign: str,
    ssid: int | None,
    destination: str,
    path: tuple[str, ...],
    information: str,
    data_type: str,
    parse_state: str,
    source_type: str,
    transport: str,
    received_at: str,
    received_epoch: int,
    raw_line: str,
    position: AprsPosition | None = None,
    source_gateway: str = "",
    parse_reason: str = "",
    messaging_capable: bool | None = None,
) -> AprsPacket:
    # observation_key excludes the APRS path so the same station payload heard
    # through different digipeater/iGate paths is one position observation.
    observation_key = _hash_text(f"{station_id}\0{information}")
    return AprsPacket(
        station_id=station_id,
        callsign=callsign,
        ssid=ssid,
        destination=destination,
        path=path,
        information=information,
        data_type=data_type,
        parse_state=parse_state,
        source_type=source_type,
        transport=transport,
        received_at=received_at,
        received_epoch=received_epoch,
        raw_packet_hash=_hash_text(raw_line),
        observation_key=observation_key,
        position=position,
        source_gateway=str(source_gateway or "").strip().upper(),
        parse_reason=parse_reason,
        messaging_capable=messaging_capable,
    )


def _decode_full_precision_coordinate(value: str, *, latitude: bool) -> float:
    pattern = _UNCOMPRESSED_LAT_RE if latitude else _UNCOMPRESSED_LON_RE
    match = pattern.fullmatch(value)
    if match is None:
        raise AprsParseError("Invalid uncompressed APRS coordinate")

    degrees = int(match.group(1))
    minutes = int(match.group(2)) + int(match.group(3)) / 100.0
    hemisphere = match.group(4)

    max_degrees = 90 if latitude else 180
    if not 0 <= degrees <= max_degrees or not 0.0 <= minutes < 60.0:
        raise AprsParseError("APRS coordinate is outside its valid degree/minute range")
    if degrees == max_degrees and minutes != 0.0:
        raise AprsParseError("APRS coordinate exceeds the pole/dateline limit")

    result = degrees + minutes / 60.0
    if hemisphere in {"S", "W"}:
        result = -result
    return result


def _position_ambiguity_digits(latitude_text: str) -> int:
    """Return APRS latitude ambiguity digit count, rejecting malformed gaps."""
    numeric = latitude_text[:-1]
    if " " not in numeric:
        return 0

    compact = numeric.replace(".", "")
    first_space = compact.find(" ")
    if first_space < 0:
        return 0
    if any(char != " " for char in compact[first_space:]):
        raise AprsParseError("Malformed APRS position ambiguity")
    ambiguity = len(compact) - first_space
    if not 1 <= ambiguity <= 4:
        raise AprsParseError("Unsupported APRS position ambiguity")
    return ambiguity


def _base91_value(char: str) -> int:
    if len(char) != 1 or not 33 <= ord(char) <= 123:
        raise AprsParseError("Invalid APRS base-91 character")
    return ord(char) - 33


def _base91_number(chars: str) -> int:
    value = 0
    for char in chars:
        value = value * 91 + _base91_value(char)
    return value


def _extract_slash_a_altitude(remainder: str) -> tuple[float | None, str]:
    """Extract ordinary APRS ``/A=nnnnnn`` altitude from a comment tail."""
    match = _ALTITUDE_RE.search(remainder)
    if match is None:
        return None, remainder
    altitude_m = round(int(match.group(1)) * 0.3048, 3)
    start, end = match.span()
    return altitude_m, remainder[:start] + remainder[end:]


def _extract_mic_e_status_altitude(remainder: str) -> tuple[float | None, str]:
    """Extract Mic-E ``xxx}`` base-91 altitude from status text when present."""
    for index in range(max(0, len(remainder) - 3)):
        if index + 4 > len(remainder) or remainder[index + 3] != "}":
            continue
        chars = remainder[index : index + 3]
        if not all(33 <= ord(char) <= 123 for char in chars):
            continue
        altitude_m = float(_base91_number(chars) - 10000)
        return altitude_m, remainder[:index] + remainder[index + 4 :]
    return None, remainder


def _mic_e_destination_digit(char: str) -> int | None:
    """Decode one Mic-E destination latitude digit; ``None`` means ambiguity."""
    if "0" <= char <= "9":
        return ord(char) - ord("0")
    if "A" <= char <= "J":
        return ord(char) - ord("A")
    if "P" <= char <= "Y":
        return ord(char) - ord("P")
    if char in {"K", "L", "Z"}:
        return None
    raise AprsParseError("Invalid Mic-E destination latitude character")


def _validate_mic_e_controls(information: str) -> None:
    """Permit only protocol-defined Mic-E binary positions in a TNC2 line."""
    binary_telemetry = len(information) > 9 and information[9] == "\x1d"
    for index, char in enumerate(information):
        code = ord(char)
        if code >= 32 or char == "\t":
            continue
        if index <= 6 and 0x1C <= code <= 0x1F:
            continue
        if binary_telemetry and 9 <= index <= 14:
            continue
        raise AprsParseError("APRS Mic-E line contains control data outside defined fields")


def _parse_mic_e_position(
    destination: str,
    information: str,
) -> tuple[AprsPosition | None, str]:
    """Decode APRS 1.0.1 Mic-E station position from TNC2 destination/info."""
    if len(information) < 9:
        raise AprsParseError("Mic-E information field is shorter than 9 bytes")

    dest_base = destination.split("-", 1)[0].upper()
    if len(dest_base) != 6:
        raise AprsParseError("Mic-E destination address must contain six encoded characters")

    decoded_digits = [_mic_e_destination_digit(char) for char in dest_base]
    ambiguity_digits = 0
    if any(value is None for value in decoded_digits):
        first_ambiguous = next(index for index, value in enumerate(decoded_digits) if value is None)
        if first_ambiguous < 2 or any(value is not None for value in decoded_digits[first_ambiguous:]):
            raise AprsParseError("Malformed Mic-E position ambiguity")
        ambiguity_digits = len(decoded_digits) - first_ambiguous
        # APRS ambiguity progressively removes precision from the right.  Use
        # the center digit 5 for plotting while retaining ambiguity_digits so
        # consumers know this is an approximate position.
        decoded_digits = [5 if value is None else value for value in decoded_digits]

    lat_digits = [int(value) for value in decoded_digits]
    latitude_degrees = lat_digits[0] * 10 + lat_digits[1]
    latitude_minutes = lat_digits[2] * 10 + lat_digits[3] + (lat_digits[4] * 10 + lat_digits[5]) / 100.0
    if latitude_degrees > 90 or latitude_minutes >= 60.0:
        raise AprsParseError("Decoded Mic-E latitude is outside valid bounds")
    latitude = latitude_degrees + latitude_minutes / 60.0
    if dest_base[3] < "P":
        latitude = -latitude

    d = ord(information[1]) - 28
    if dest_base[4] >= "P":
        d += 100
    if 180 <= d <= 189:
        d -= 80
    elif 190 <= d <= 199:
        d -= 190

    minute = ord(information[2]) - 28
    if minute >= 60:
        minute -= 60
    hundredth = ord(information[3]) - 28
    if not 0 <= d <= 179 or not 0 <= minute <= 59 or not 0 <= hundredth <= 99:
        raise AprsParseError("Decoded Mic-E longitude is outside valid bounds")

    # The latitude ambiguity level also applies to longitude.  Center the
    # corresponding unknown decimal-minute digits for display while preserving
    # the ambiguity count in the normalized position.
    if ambiguity_digits == 1:
        hundredth = (hundredth // 10) * 10 + 5
    elif ambiguity_digits == 2:
        hundredth = 50
    elif ambiguity_digits == 3:
        minute = (minute // 10) * 10 + 5
        hundredth = 50
    elif ambiguity_digits >= 4:
        minute = 30
        hundredth = 50
    longitude = d + (minute + hundredth / 100.0) / 60.0
    if dest_base[5] >= "P":
        longitude = -longitude

    sp = ord(information[4]) - 28
    dc = ord(information[5]) - 28
    se = ord(information[6]) - 28
    speed_knots = sp * 10 + dc // 10
    course = (dc % 10) * 100 + se
    if speed_knots >= 800:
        speed_knots -= 800
    if course >= 400:
        course -= 400
    if not 0 <= speed_knots <= 799 or not 0 <= course <= 360:
        raise AprsParseError("Decoded Mic-E course/speed is outside valid bounds")

    symbol_code = information[7]
    symbol_table = information[8]
    if not symbol_code.isprintable() or not symbol_table.isprintable():
        raise AprsParseError("Mic-E symbol bytes must be printable")

    remainder = information[9:]
    altitude_m, remainder = _extract_mic_e_status_altitude(remainder)
    slash_altitude_m, remainder = _extract_slash_a_altitude(remainder)
    if altitude_m is None:
        altitude_m = slash_altitude_m

    return AprsPosition(
        latitude=latitude,
        longitude=longitude,
        symbol_table=symbol_table,
        symbol_code=symbol_code,
        altitude_m=altitude_m,
        course_deg=course,
        speed_kmh=round(speed_knots * 1.852, 3),
        packet_time_raw=None,
        comment=remainder.strip(),
        ambiguity_digits=ambiguity_digits,
        position_format="mic_e",
        weather=None,
    ), ""


def _looks_compressed(body: str) -> bool:
    if len(body) < 13:
        return False
    candidate = body[:13]
    if not candidate[0].isprintable() or not candidate[9].isprintable():
        return False
    if not all(33 <= ord(char) <= 123 for char in candidate[1:9]):
        return False

    # APRS 1.0.1: literal-space c means there is no course/speed/range/
    # altitude and *the complete csT triplet is ignored*.  The s/T filler
    # characters therefore need not be base-91 in this branch.
    if candidate[10] == " ":
        return True
    if not 33 <= ord(candidate[10]) <= 123:
        return False
    return all(33 <= ord(char) <= 123 for char in candidate[11:13])


def _numeric_weather_token(value: str) -> int | None:
    if not value or any(char in ". V" for char in value):
        return None
    if not value.isdigit():
        return None
    return int(value)


def _temperature_weather_token(value: str) -> int | None:
    if not value or any(char in ". V" for char in value):
        return None
    if value.startswith("-"):
        if len(value) != 3 or not value[1:].isdigit():
            return None
        return -int(value[1:])
    if not value.isdigit():
        return None
    return int(value)


def _weather_from_tail(
    remainder: str,
    *,
    wind_direction_deg: int | None,
    wind_speed_knots: float | None,
) -> tuple[AprsWeather, str]:
    values: dict[str, float | int | None] = {
        "wind_direction_deg": wind_direction_deg,
        "wind_speed_kmh": (
            round(float(wind_speed_knots) * 1.852, 3)
            if wind_speed_knots is not None
            else None
        ),
        "gust_kmh": None,
        "temperature_c": None,
        "rain_last_hour_mm": None,
        "rain_last_24h_mm": None,
        "rain_since_midnight_mm": None,
        "humidity_percent": None,
        "pressure_hpa": None,
    }

    text = remainder
    while text and text[0] in _WEATHER_FIELDS:
        marker = text[0]
        width, name = _WEATHER_FIELDS[marker]
        if len(text) < width + 1:
            break
        token = text[1 : width + 1]

        if name == "temperature":
            numeric = _temperature_weather_token(token)
        else:
            numeric = _numeric_weather_token(token)

        # A syntactically weather-like marker with an invalid fixed-width value
        # ends the structured prefix; the rest remains human-readable comment.
        if numeric is None and not all(char in ". V" for char in token):
            break

        if numeric is not None:
            if name == "gust":
                values["gust_kmh"] = round(numeric * 1.609344, 3)
            elif name == "temperature":
                values["temperature_c"] = round((numeric - 32.0) * 5.0 / 9.0, 3)
            elif name == "rain_last_hour":
                values["rain_last_hour_mm"] = round(numeric * 0.254, 3)
            elif name == "rain_last_24h":
                values["rain_last_24h_mm"] = round(numeric * 0.254, 3)
            elif name == "rain_since_midnight":
                values["rain_since_midnight_mm"] = round(numeric * 0.254, 3)
            elif name == "humidity":
                values["humidity_percent"] = 100 if numeric == 0 else numeric
            elif name == "pressure":
                values["pressure_hpa"] = round(numeric / 10.0, 1)

        text = text[width + 1 :]

    return AprsWeather(**values), text.strip()


def _parse_uncompressed_position(
    body: str,
    *,
    packet_time_raw: str | None,
) -> tuple[AprsPosition | None, str]:
    if len(body) < 19:
        if _looks_compressed(body):
            return _parse_compressed_position(body, packet_time_raw=packet_time_raw), ""
        raise AprsParseError("APRS position field is too short")

    latitude_text = body[:8]
    symbol_table = body[8]
    longitude_text = body[9:18]
    symbol_code = body[18]
    remainder = body[19:]

    if not (latitude_text[-1:] in {"N", "S"} and latitude_text[4:5] == "."):
        if _looks_compressed(body):
            return _parse_compressed_position(body, packet_time_raw=packet_time_raw), ""
        raise AprsParseError("Unsupported or malformed APRS position encoding")

    ambiguity_digits = _position_ambiguity_digits(latitude_text)
    if ambiguity_digits:
        return None, f"position_ambiguity_{ambiguity_digits}"

    if " " in longitude_text:
        return None, "position_ambiguity_longitude"

    latitude = _decode_full_precision_coordinate(latitude_text, latitude=True)
    longitude = _decode_full_precision_coordinate(longitude_text, latitude=False)

    course_deg: int | None = None
    speed_kmh: float | None = None
    weather: AprsWeather | None = None

    extension_match = _COURSE_SPEED_RE.match(remainder)
    if extension_match:
        candidate_course = int(extension_match.group(1))
        candidate_speed = int(extension_match.group(2))
        if 0 <= candidate_course <= 360:
            if symbol_code == "_":
                # In a complete weather report this 7-byte extension is wind,
                # not station motion.
                weather, weather_comment = _weather_from_tail(
                    extension_match.group(3),
                    wind_direction_deg=candidate_course,
                    wind_speed_knots=float(candidate_speed),
                )
                remainder = weather_comment
            else:
                course_deg = candidate_course
                speed_kmh = round(candidate_speed * 1.852, 3)
                remainder = extension_match.group(3)
    elif symbol_code == "_":
        weather_match = _WEATHER_WIND_RE.match(remainder)
        if weather_match:
            direction = _numeric_weather_token(weather_match.group(1))
            speed = _numeric_weather_token(weather_match.group(2))
            weather, weather_comment = _weather_from_tail(
                weather_match.group(3),
                wind_direction_deg=direction,
                wind_speed_knots=float(speed) if speed is not None else None,
            )
            remainder = weather_comment

    altitude_m, remainder = _extract_slash_a_altitude(remainder)

    comment = remainder.strip()
    return AprsPosition(
        latitude=latitude,
        longitude=longitude,
        symbol_table=symbol_table,
        symbol_code=symbol_code,
        altitude_m=altitude_m,
        course_deg=course_deg,
        speed_kmh=speed_kmh,
        packet_time_raw=packet_time_raw,
        comment=comment,
        ambiguity_digits=0,
        position_format="uncompressed",
        weather=weather,
    ), ""


def _parse_compressed_position(
    body: str,
    *,
    packet_time_raw: str | None,
) -> AprsPosition:
    if not _looks_compressed(body):
        raise AprsParseError("Invalid APRS compressed position field")

    candidate = body[:13]
    symbol_table = candidate[0]
    lat_chars = candidate[1:5]
    lon_chars = candidate[5:9]
    symbol_code = candidate[9]
    c_char = candidate[10]
    s_char = candidate[11]
    t_char = candidate[12]
    remainder = body[13:].strip()

    latitude = 90.0 - _base91_number(lat_chars) / 380926.0
    longitude = -180.0 + _base91_number(lon_chars) / 190463.0
    if not -90.0 <= latitude <= 90.0 or not -180.0 <= longitude <= 180.0:
        raise AprsParseError("Decoded APRS compressed position is outside valid bounds")

    altitude_m: float | None = None
    course_deg: int | None = None
    speed_kmh: float | None = None
    weather: AprsWeather | None = None

    # Literal space is a protocol-defined sentinel: csT bytes are ignored.
    if c_char != " ":
        c_value = _base91_value(c_char)
        s_value = _base91_value(s_char)
        t_value = _base91_value(t_char)
        nmea_source = (t_value >> 3) & 0x03

        if nmea_source == 0b10:
            cs_value = c_value * 91 + s_value
            altitude_ft = math.pow(1.002, cs_value)
            altitude_m = round(altitude_ft * 0.3048, 3)
        elif c_value <= 89:
            encoded_direction = c_value * 4
            encoded_speed_knots = math.pow(1.08, s_value) - 1.0
            if symbol_code == "_":
                weather = AprsWeather(
                    wind_direction_deg=encoded_direction,
                    wind_speed_kmh=round(encoded_speed_knots * 1.852, 3),
                )
            else:
                course_deg = encoded_direction
                speed_kmh = round(encoded_speed_knots * 1.852, 3)
        # c == 90 ('{') is pre-calculated radio range. A1.4 preserves the
        # position but intentionally does not coerce range into motion data.

    # Complete compressed weather may append ordinary weather tokens after csT.
    if symbol_code == "_":
        base_weather = weather or AprsWeather()
        parsed_weather, weather_comment = _weather_from_tail(
            remainder,
            wind_direction_deg=base_weather.wind_direction_deg,
            wind_speed_knots=(
                base_weather.wind_speed_kmh / 1.852
                if base_weather.wind_speed_kmh is not None
                else None
            ),
        )
        weather = parsed_weather
        remainder = weather_comment

    slash_altitude_m, remainder = _extract_slash_a_altitude(remainder)
    if altitude_m is None:
        altitude_m = slash_altitude_m

    return AprsPosition(
        latitude=latitude,
        longitude=longitude,
        symbol_table=symbol_table,
        symbol_code=symbol_code,
        altitude_m=altitude_m,
        course_deg=course_deg,
        speed_kmh=speed_kmh,
        packet_time_raw=packet_time_raw,
        comment=remainder,
        ambiguity_digits=0,
        position_format="compressed",
        weather=weather,
    )


def parse_tnc2_line(
    line: str,
    *,
    source_type: str = "fixture",
    transport: str = "unknown",
    source_gateway: str = "",
    received_at: str | None = None,
    received_epoch: int | None = None,
) -> AprsPacket:
    """Parse one human-readable TNC2 APRS line into the read-only data model.

    A1.5b supports full-precision uncompressed, standard compressed and Mic-E
    station positions. Complete weather reports with a position are normalized
    into dedicated weather fields. Objects/items and other APRS entity types
    remain non-position until explicitly implemented.
    """
    raw_line = str(line or "").rstrip("\r\n")
    if not raw_line or len(raw_line) > 1024:
        raise AprsParseError("APRS line is empty or unreasonably long")
    source_type = normalize_source_type(source_type)
    transport = normalize_transport(transport)

    if received_at is None:
        received_at = now_iso()
    if received_epoch is None:
        received_epoch = _iso_to_epoch(received_at)
    else:
        received_epoch = int(received_epoch)
        _iso_to_epoch(received_at)

    match = _TNC2_RE.fullmatch(raw_line)
    if match is None:
        raise AprsParseError("Invalid TNC2 APRS line")

    header_text = raw_line.split(":", 1)[0]
    if any(ord(char) < 32 for char in header_text):
        raise AprsParseError("APRS TNC2 header contains control characters")

    station_id, callsign, ssid = canonical_station_id(match.group(1))
    route = [part.strip() for part in match.group(2).split(",")]
    if not route or not route[0]:
        raise AprsParseError("APRS destination is missing")
    destination = route[0].upper()
    if len(destination) > 16 or not destination.isprintable():
        raise AprsParseError("Invalid APRS destination")
    path = normalize_path(route[1:])

    information = match.group(3)
    data_type = information[0]
    if any(ord(char) < 32 and char != "\t" for char in information):
        if data_type not in MIC_E_DTIS:
            raise AprsParseError("APRS non-Mic-E information contains control characters")
        _validate_mic_e_controls(information)
    messaging_capable = data_type in MESSAGING_DTIS if data_type in POSITION_DTIS else None

    common: dict[str, Any] = {
        "station_id": station_id,
        "callsign": callsign,
        "ssid": ssid,
        "destination": destination,
        "path": path,
        "information": information,
        "data_type": data_type,
        "source_type": source_type,
        "transport": transport,
        "received_at": received_at,
        "received_epoch": received_epoch,
        "raw_line": raw_line,
        "source_gateway": source_gateway,
        "messaging_capable": messaging_capable,
    }

    if data_type in MIC_E_DTIS:
        position, unsupported_reason = _parse_mic_e_position(destination, information)
        if position is None:
            return _make_packet(
                **common,
                parse_state="unsupported_position",
                parse_reason=unsupported_reason,
            )
        return _make_packet(
            **common,
            parse_state="position",
            position=position,
        )

    if data_type not in POSITION_DTIS:
        return _make_packet(
            **common,
            parse_state="non_position",
            parse_reason="data_type_not_position",
        )

    body = information[1:]
    packet_time_raw: str | None = None
    if data_type in TIMESTAMPED_DTIS:
        if len(body) < 7:
            raise AprsParseError("Timestamped APRS position is missing its timestamp")
        packet_time_raw = body[:7]
        if _TIMESTAMP_RE.fullmatch(packet_time_raw) is None:
            raise AprsParseError("Unsupported or invalid APRS position timestamp")
        body = body[7:]

    position, unsupported_reason = _parse_uncompressed_position(
        body,
        packet_time_raw=packet_time_raw,
    )
    if position is None:
        return _make_packet(
            **common,
            parse_state="unsupported_position",
            parse_reason=unsupported_reason,
        )

    return _make_packet(
        **common,
        parse_state="position",
        position=position,
    )
