#!/usr/bin/env python3

import json
import re
from datetime import datetime, timezone


SCHEMA = "gutchat.aprs.rx.v1"
DECODER_NAME = "direwolf"
DECODER_VERSION_CONTRACT = "1.7+dfsg-2build2"

MAX_LINE_CHARS = 2048

HEADER_RE = re.compile(
    r"^\[(?P<channel>[0-9]+)\.(?P<demod>[0-9]+)\][ \t]+(?P<body>.+)$"
)

CALL_RE = re.compile(
    r"^[A-Z0-9]{1,6}(?:-(?P<ssid>[0-9]{1,2}))?$"
)

DEST_RE = re.compile(
    r"^[A-Z0-9]{1,9}(?:-(?P<ssid>[0-9]{1,2}))?$"
)

PATH_RE = re.compile(
    r"^[A-Z0-9]{1,9}(?:-(?P<ssid>[0-9]{1,2}))?\*?$"
)


class ParseError(ValueError):
    pass


def _check_ssid(match, field):
    if match is None:
        raise ParseError(f"invalid {field}")

    ssid = match.groupdict().get("ssid")

    if ssid is not None and not (0 <= int(ssid) <= 15):
        raise ParseError(f"{field} SSID outside 0..15")


def _reject_controls(text):
    for ch in text:
        code = ord(ch)
        if code < 0x20 or code == 0x7f:
            raise ParseError("control character in decoder frame")


def parse_direwolf_line(line, received_at):
    """
    Parse one Dire Wolf console-output line.

    Return:
      dict  -> accepted decoded RX frame
      None  -> diagnostic/non-frame output

    Raise ParseError for a line that has the expected decoded-frame
    envelope but violates the strict A2 ingress contract.
    """

    if not isinstance(line, str):
        raise ParseError("input is not text")

    line = line.rstrip("\r\n")

    if not line:
        return None

    if len(line) > MAX_LINE_CHARS:
        raise ParseError("decoder line exceeds maximum length")

    match = HEADER_RE.match(line)

    if match is None:
        # Non-frame Dire Wolf output is diagnostic-only.
        return None

    channel = int(match.group("channel"))
    demod = int(match.group("demod"))
    raw_tnc2 = match.group("body")

    # e3 has exactly CHANNEL 0 and CHANNEL 1.
    if channel not in (0, 1):
        raise ParseError("decoder channel outside configured set")

    _reject_controls(raw_tnc2)

    if ":" not in raw_tnc2:
        raise ParseError("missing TNC2 information separator")

    address_part, information = raw_tnc2.split(":", 1)

    if ">" not in address_part:
        raise ParseError("missing TNC2 source/destination separator")

    source, remainder = address_part.split(">", 1)

    if not source:
        raise ParseError("missing source")

    if not remainder:
        raise ParseError("missing destination")

    route = remainder.split(",")
    destination = route[0]
    path = route[1:]

    source_match = CALL_RE.fullmatch(source)
    _check_ssid(source_match, "source")

    dest_match = DEST_RE.fullmatch(destination)
    _check_ssid(dest_match, "destination")

    for hop in path:
        if not hop:
            raise ParseError("empty path component")

        hop_match = PATH_RE.fullmatch(hop)
        _check_ssid(hop_match, "path component")

    if information == "":
        raise ParseError("empty APRS information field")

    # received_at belongs to the ingress boundary, not to APRS payload time.
    try:
        parsed_time = datetime.fromisoformat(
            received_at.replace("Z", "+00:00")
        )
    except Exception as exc:
        raise ParseError("invalid received_at") from exc

    if parsed_time.tzinfo is None:
        raise ParseError("received_at must be timezone-aware")

    return {
        "schema": SCHEMA,
        "received_at": received_at,
        "network": "classic_aprs_rf",
        "direction": "rx",
        "source": source,
        "destination": destination,
        "path": path,
        "information": information,
        "decoder": {
            "name": DECODER_NAME,
            "version_contract": DECODER_VERSION_CONTRACT,
            "channel": channel,
            "demod": demod,
        },
        "raw_tnc2": raw_tnc2,
    }


def now_utc_iso():
    return datetime.now(timezone.utc).isoformat()


def json_line(event):
    return json.dumps(
        event,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
