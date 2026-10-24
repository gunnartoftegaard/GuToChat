#!/usr/bin/env python3
"""Pure, network-free APRS receive-iGate eligibility policy for GuToChat.

This module does not open sockets, read the production database, transmit RF,
or modify services/configuration.  It converts one already-persisted A2 receipt
into either a fail-closed rejection or a proposed APRS-IS TNC2 line.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Mapping


POLICY_VERSION = "gutchat.aprs.igate.policy.v1.2"
RECEIPT_KEY_SCHEMA = "gutchat.aprs.receipt.key.v1"
EVENT_SCHEMA = "gutchat.aprs.rx.v1"
EXPECTED_NETWORK = "classic_aprs_rf"
EXPECTED_DIRECTION = "rx"
EXPECTED_RECEIVER_ID = "BASE-A2-RX"
EXPECTED_DECODER_NAME = "direwolf"
EXPECTED_DECODER_MONITOR_CONTRACT = "direwolf-1.7-aprs-monitor-v1"
EXPECTED_DIREWOLF_PACKAGE = "direwolf"
EXPECTED_DIREWOLF_PACKAGE_VERSION = "1.7+dfsg-2+deb13u1"
EXPECTED_DIREWOLF_ARCH = "arm64"
EXPECTED_DIREWOLF_BINARY_SHA256 = (
    "4b7d53b5bd4d7d1fe6819a780bbdd680605d2263539dca36dca7b3d9e3637305"
)

EXPECTED_DIREWOLF_CONFIG_SHA256 = (
    "0283df03be5cd418ed7c24e32d0e980abfd95a185223d7791ad0304790ddc891"
)
EXPECTED_PARSER_SHA256 = "7275935613b6bad8441295b2f7c1885b159362efd05339c80c4302f82ae34422"
EXPECTED_ADAPTER_SHA256 = "60ea81dc0470a2416bfc4f31ad63a1d57072f1788194ac6ff5d0d6f6c3c01b64"

ALLOWED_DOMAIN_RESULTS = frozenset({"created", "updated", "duplicate", "older"})
MAX_RECEIPT_AGE_SECONDS = 120
MAX_FUTURE_SKEW_SECONDS = 10
MAX_APRS_IS_WIRE_BYTES = 512  # includes trailing CRLF

CALL_RE = re.compile(r"^[A-Z0-9]{1,6}(?:-(?P<ssid>[0-9]{1,2}))?$")
APRS_IS_LOGIN_RE = re.compile(r"^[A-Za-z0-9]{1,9}(?:-[A-Za-z0-9]{1,2})?$")
DEST_RE = re.compile(r"^[A-Z0-9]{1,9}(?:-(?P<ssid>[0-9]{1,2}))?$")
PATH_RE = re.compile(r"^[A-Za-z0-9]{1,9}(?:-(?P<ssid>[0-9]{1,2}))?\*?$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
Q_CONSTRUCT_RE = re.compile(r"^qA[A-Za-z]$", re.IGNORECASE)


@dataclass(frozen=True)
class RuntimeProvenance:
    direwolf_package: str
    direwolf_package_version: str
    direwolf_architecture: str
    direwolf_binary_sha256: str
    direwolf_config_sha256: str
    parser_sha256: str
    adapter_sha256: str


@dataclass(frozen=True)
class PolicyDecision:
    eligible: bool
    reason: str
    proposed_tnc2: str | None = None
    proposed_wire: bytes | None = None
    uplink_key: str | None = None
    third_party_stripped: bool = False


def _reject(reason: str) -> PolicyDecision:
    return PolicyDecision(False, reason)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "strict")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _check_ssid(match: re.Match[str] | None) -> bool:
    if match is None:
        return False
    ssid = match.groupdict().get("ssid")
    return ssid is None or 0 <= int(ssid) <= 15


def _valid_igate_call(call: str) -> bool:
    # APRS-IS textual login/callSSID rules permit a 1-2 alphanumeric suffix.
    # This is deliberately separate from an over-the-air AX.25 numeric SSID.
    return isinstance(call, str) and APRS_IS_LOGIN_RE.fullmatch(call) is not None


def _ascii_tnc2_safe(text: str) -> bool:
    return all(0x20 <= ord(ch) <= 0x7e for ch in text)


def _parse_tnc2(raw: str) -> tuple[str, str, list[str], str] | None:
    if not isinstance(raw, str) or not raw or "\r" in raw or "\n" in raw:
        return None
    if ":" not in raw:
        return None
    address, information = raw.split(":", 1)
    if not information or ">" not in address:
        return None
    source, remainder = address.split(">", 1)
    if not source or not remainder:
        return None
    route = remainder.split(",")
    destination = route[0]
    path = route[1:]
    if not _check_ssid(CALL_RE.fullmatch(source)):
        return None
    if not _check_ssid(DEST_RE.fullmatch(destination)):
        return None
    for hop in path:
        if not hop or not _check_ssid(PATH_RE.fullmatch(hop)):
            return None
    return source, destination, path, information


def _blocked_path_reason(path: list[str], prefix: str = "PATH") -> str | None:
    for hop in path:
        bare = hop[:-1] if hop.endswith("*") else hop
        upper = bare.upper()
        if upper in {"TCPIP", "TCPXX"}:
            return f"{prefix}_TCPIP_TCPXX"
        if upper in {"NOGATE", "RFONLY"}:
            return f"{prefix}_NOGATE_RFONLY"
        if bare.upper() == "I":
            return f"{prefix}_LEGACY_I"
        if Q_CONSTRUCT_RE.fullmatch(bare):
            return f"{prefix}_Q_CONSTRUCT"
    return None


def _append_qao(
    source: str,
    destination: str,
    path: list[str],
    information: str,
    igate_call: str,
) -> str:
    route = [destination, *path, "qAO", igate_call]
    return f"{source}>{','.join(route)}:{information}"


def runtime_provenance_matches_expected(p: RuntimeProvenance) -> bool:
    """Return True only for the exact production provenance contract."""
    return (
        p.direwolf_package == EXPECTED_DIREWOLF_PACKAGE
        and p.direwolf_package_version == EXPECTED_DIREWOLF_PACKAGE_VERSION
        and p.direwolf_architecture == EXPECTED_DIREWOLF_ARCH
        and p.direwolf_binary_sha256 == EXPECTED_DIREWOLF_BINARY_SHA256
        and p.direwolf_config_sha256 == EXPECTED_DIREWOLF_CONFIG_SHA256
        and p.parser_sha256 == EXPECTED_PARSER_SHA256
        and p.adapter_sha256 == EXPECTED_ADAPTER_SHA256
    )


def runtime_provenance_fingerprint(p: RuntimeProvenance) -> str:
    """Stable SHA256 identity for a fully specified runtime provenance tuple."""
    return _sha256_text(
        _canonical_json(
            {
                "direwolf_package": p.direwolf_package,
                "direwolf_package_version": p.direwolf_package_version,
                "direwolf_architecture": p.direwolf_architecture,
                "direwolf_binary_sha256": p.direwolf_binary_sha256,
                "direwolf_config_sha256": p.direwolf_config_sha256,
                "parser_sha256": p.parser_sha256,
                "adapter_sha256": p.adapter_sha256,
            }
        )
    )


# Backwards-compatible private alias for callers/tests that imported the old name.
def _runtime_provenance_ok(p: RuntimeProvenance) -> bool:
    return runtime_provenance_matches_expected(p)


def _verify_receipt_integrity(receipt: Mapping[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    required = {
        "receipt_key",
        "event_schema",
        "network",
        "direction",
        "receiver_id",
        "received_at",
        "raw_tnc2",
        "raw_tnc2_hash",
        "event_json",
        "event_hash",
        "processing_state",
        "domain_store_result",
        "last_error_code",
    }
    if not required.issubset(receipt):
        return None, "RECEIPT_FIELDS_MISSING"

    if receipt["event_schema"] != EVENT_SCHEMA:
        return None, "RECEIPT_EVENT_SCHEMA"
    if receipt["network"] != EXPECTED_NETWORK:
        return None, "RECEIPT_NETWORK"
    if receipt["direction"] != EXPECTED_DIRECTION:
        return None, "RECEIPT_DIRECTION"
    if receipt["receiver_id"] != EXPECTED_RECEIVER_ID:
        return None, "RECEIPT_RECEIVER_ID"
    if receipt["processing_state"] != "domain_persisted":
        return None, "RECEIPT_NOT_DOMAIN_PERSISTED"
    if receipt["domain_store_result"] not in ALLOWED_DOMAIN_RESULTS:
        return None, "RECEIPT_DOMAIN_RESULT"
    if receipt["last_error_code"] not in (None, ""):
        return None, "RECEIPT_LAST_ERROR"

    for key in ("receipt_key", "raw_tnc2_hash", "event_hash"):
        value = receipt[key]
        if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None:
            return None, f"RECEIPT_{key.upper()}_FORMAT"

    raw = receipt["raw_tnc2"]
    event_json = receipt["event_json"]
    if not isinstance(raw, str) or not raw or "\r" in raw or "\n" in raw:
        return None, "RECEIPT_RAW_TNC2"
    if not isinstance(event_json, str) or not event_json:
        return None, "RECEIPT_EVENT_JSON"

    if _sha256_text(raw) != receipt["raw_tnc2_hash"]:
        return None, "RECEIPT_RAW_HASH"
    if _sha256_text(event_json) != receipt["event_hash"]:
        return None, "RECEIPT_EVENT_HASH"

    try:
        event = json.loads(event_json)
        canonical_event = _canonical_json(event)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None, "RECEIPT_EVENT_JSON_INVALID"
    if canonical_event != event_json:
        return None, "RECEIPT_EVENT_JSON_NONCANONICAL"

    identity_json = _canonical_json(
        {
            "receipt_key_schema": RECEIPT_KEY_SCHEMA,
            "receiver_id": receipt["receiver_id"],
            "event": event,
        }
    )
    if _sha256_text(identity_json) != receipt["receipt_key"]:
        return None, "RECEIPT_KEY_MISMATCH"

    if not isinstance(event, dict):
        return None, "EVENT_NOT_OBJECT"
    pairs = (
        ("schema", "event_schema"),
        ("network", "network"),
        ("direction", "direction"),
        ("received_at", "received_at"),
        ("raw_tnc2", "raw_tnc2"),
    )
    for event_key, receipt_key in pairs:
        if event.get(event_key) != receipt[receipt_key]:
            return None, f"EVENT_RECEIPT_MISMATCH_{event_key.upper()}"

    return event, None


def _freshness_reason(received_at: str, now: datetime) -> str | None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    try:
        received = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return "RECEIVED_AT_INVALID"
    if received.tzinfo is None or received.utcoffset() is None:
        return "RECEIVED_AT_NAIVE"
    age = (now.astimezone(timezone.utc) - received.astimezone(timezone.utc)).total_seconds()
    if age > MAX_RECEIPT_AGE_SECONDS:
        return "RECEIPT_STALE"
    if age < -MAX_FUTURE_SKEW_SECONDS:
        return "RECEIPT_FROM_FUTURE"
    return None


def evaluate_receipt(
    receipt: Mapping[str, Any],
    *,
    igate_call: str,
    provenance: RuntimeProvenance,
    now: datetime,
) -> PolicyDecision:
    """Return a deterministic, fail-closed receive-iGate policy decision."""
    if not _valid_igate_call(igate_call):
        return _reject("IGATE_CALL_INVALID")
    if not _runtime_provenance_ok(provenance):
        return _reject("RUNTIME_PROVENANCE_MISMATCH")

    event, integrity_error = _verify_receipt_integrity(receipt)
    if integrity_error is not None:
        return _reject(integrity_error)
    assert event is not None

    freshness = _freshness_reason(receipt["received_at"], now)
    if freshness is not None:
        return _reject(freshness)

    decoder = event.get("decoder")
    if not isinstance(decoder, dict):
        return _reject("DECODER_METADATA_MISSING")
    if decoder.get("name") != EXPECTED_DECODER_NAME:
        return _reject("DECODER_NAME_MISMATCH")
    if decoder.get("provenance_status") != "verified":
        return _reject("DECODER_PROVENANCE_UNVERIFIED")
    if decoder.get("monitor_contract") != EXPECTED_DECODER_MONITOR_CONTRACT:
        return _reject("DECODER_MONITOR_CONTRACT_MISMATCH")
    if decoder.get("package") != EXPECTED_DIREWOLF_PACKAGE:
        return _reject("DECODER_PACKAGE_MISMATCH")
    if decoder.get("package_version") != EXPECTED_DIREWOLF_PACKAGE_VERSION:
        return _reject("DECODER_PACKAGE_VERSION_MISMATCH")
    if decoder.get("architecture") != EXPECTED_DIREWOLF_ARCH:
        return _reject("DECODER_ARCHITECTURE_MISMATCH")
    if decoder.get("binary_sha256") != EXPECTED_DIREWOLF_BINARY_SHA256:
        return _reject("DECODER_BINARY_SHA256_MISMATCH")

    raw = event.get("raw_tnc2")
    if not isinstance(raw, str) or not _ascii_tnc2_safe(raw):
        return _reject("NON_ASCII_TNC2_UNSAFE")
    parsed = _parse_tnc2(raw)
    if parsed is None:
        return _reject("RAW_TNC2_INVALID")
    source, destination, path, information = parsed

    if (
        event.get("source") != source
        or event.get("destination") != destination
        or event.get("path") != path
        or event.get("information") != information
    ):
        return _reject("EVENT_TNC2_MISMATCH")

    # Pinned Dire Wolf 1.7 monitor-output contract: non-APRS frames are
    # rendered with a parenthesized frame description immediately after ':'.
    # Dire Wolf's ax25_is_aprs() itself requires UI control 0x03 and PID 0xf0.
    # Rejecting '(' may create safe false negatives for unusual payloads, but
    # avoids accepting a non-APRS monitor line when control/PID are not carried
    # explicitly by the A2 event schema.
    if information.startswith("("):
        return _reject("AX25_UI_PID_NOT_PROVEN")

    outer_path_reason = _blocked_path_reason(path, "RF_PATH")
    if outer_path_reason is not None:
        return _reject(outer_path_reason)

    third_party = information.startswith("}")
    if third_party:
        inner_raw = information[1:]
        if inner_raw.startswith("}") or not inner_raw:
            return _reject("THIRD_PARTY_NESTED_OR_EMPTY")
        inner = _parse_tnc2(inner_raw)
        if inner is None:
            return _reject("THIRD_PARTY_INVALID")
        i_source, i_destination, i_path, i_information = inner
        if i_information.startswith("}"):
            return _reject("THIRD_PARTY_NESTED")
        if i_information.startswith("("):
            return _reject("THIRD_PARTY_AX25_UI_PID_NOT_PROVEN")
        inner_path_reason = _blocked_path_reason(i_path, "THIRD_PARTY_PATH")
        if inner_path_reason is not None:
            return _reject(inner_path_reason)
        if i_information.startswith("?"):
            return _reject("GENERIC_QUERY")
        proposed = _append_qao(
            i_source, i_destination, i_path, i_information, igate_call
        )
    else:
        if information.startswith("?"):
            return _reject("GENERIC_QUERY")
        proposed = _append_qao(
            source, destination, path, information, igate_call
        )

    wire = (proposed + "\r\n").encode("utf-8", "strict")
    if len(wire) > MAX_APRS_IS_WIRE_BYTES:
        return _reject("APRS_IS_WIRE_TOO_LONG")

    uplink_material = _canonical_json(
        {
            "policy_version": POLICY_VERSION,
            "receipt_key": receipt["receipt_key"],
            "proposed_tnc2": proposed,
        }
    )
    uplink_key = _sha256_text(uplink_material)

    return PolicyDecision(
        eligible=True,
        reason="ELIGIBLE",
        proposed_tnc2=proposed,
        proposed_wire=wire,
        uplink_key=uplink_key,
        third_party_stripped=third_party,
    )
