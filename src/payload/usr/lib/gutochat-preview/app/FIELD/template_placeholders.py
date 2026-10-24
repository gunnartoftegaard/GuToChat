#!/usr/bin/env python3
"""Pure validation and rendering for emergency-template placeholders."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
from typing import Iterable


ALLOWED_PLACEHOLDERS = (
    "KALLESIGNAL",
    "DATO",
    "TID",
    "MOTTAKER",
    "POSISJON",
)
PRIVACY_DECIMAL_PLACES = 3
STORED_DECIMAL_PLACES = 7
_MAX_CALLSIGN_LENGTH = 40
_MAX_RECIPIENT_LENGTH = 160
_COMPLETE_BRACED_TOKEN = re.compile(r"\{([^{}]*)\}")
_PLACEHOLDER_NAME = re.compile(r"[A-ZÆØÅ0-9_]+")
_MALFORMED_OPENING = re.compile(r"\{[A-ZÆØÅ0-9_]+(?:\s|$)")


@dataclass(frozen=True)
class TemplatePreview:
    """Rendered template text and the fixed local time used for expansion."""

    text: str
    placeholders: tuple[str, ...]
    preview_time: datetime


def _normalize_single_line(
    value: str | None,
    *,
    field_name: str,
    max_length: int,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} mangler")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} mangler")
    if "\n" in normalized or "\r" in normalized:
        raise ValueError(f"{field_name} kan ikke inneholde linjeskift")
    if len(normalized) > max_length:
        raise ValueError(f"{field_name} er for langt")
    return normalized


def _validate_preview_time(value: datetime | None) -> datetime:
    preview_time = value or datetime.now().astimezone()
    if not isinstance(preview_time, datetime):
        raise ValueError("Forhåndsvisningstid må være et datetime-objekt")
    if preview_time.tzinfo is None or preview_time.utcoffset() is None:
        raise ValueError("Forhåndsvisningstid må inneholde tidssone")
    return preview_time


def extract_placeholders(template_text: str) -> tuple[str, ...]:
    """Return known placeholders in first-use order and reject unknown names."""
    if not isinstance(template_text, str):
        raise ValueError("Maltekst må være tekst")

    found: list[str] = []
    for match in _COMPLETE_BRACED_TOKEN.finditer(template_text):
        candidate = match.group(1)
        if not _PLACEHOLDER_NAME.fullmatch(candidate):
            continue
        if candidate not in ALLOWED_PLACEHOLDERS:
            raise ValueError(f"Ukjent plassholder: {{{candidate}}}")
        if candidate not in found:
            found.append(candidate)

    # Uppercase brace syntax is reserved for placeholders. Ordinary lower-case
    # braces remain literal, but an unfinished uppercase token is rejected.
    masked = _COMPLETE_BRACED_TOKEN.sub("", template_text)
    if _MALFORMED_OPENING.search(masked):
        raise ValueError("Ugyldig eller ufullstendig plassholder")
    return tuple(found)


def _format_coordinate(value_i: int, *, exact: bool) -> str:
    if isinstance(value_i, bool) or not isinstance(value_i, int):
        raise ValueError("Koordinat må være et heltall")
    value = Decimal(value_i) / Decimal(10**STORED_DECIMAL_PLACES)
    decimal_places = STORED_DECIMAL_PLACES if exact else PRIVACY_DECIMAL_PLACES
    quantum = Decimal(1).scaleb(-decimal_places)
    rounded = value.quantize(quantum, rounding=ROUND_HALF_UP)
    return format(rounded, f".{decimal_places}f")


def format_position(
    latitude_i: int,
    longitude_i: int,
    *,
    exact: bool = False,
) -> str:
    """Format stored integer coordinates for reduced or full stored precision."""
    if not -900_000_000 <= latitude_i <= 900_000_000:
        raise ValueError("Breddegrad er utenfor gyldig område")
    if not -1_800_000_000 <= longitude_i <= 1_800_000_000:
        raise ValueError("Lengdegrad er utenfor gyldig område")
    latitude = _format_coordinate(latitude_i, exact=exact)
    longitude = _format_coordinate(longitude_i, exact=exact)
    return f"{latitude}, {longitude}"


def render_template(
    template_text: str,
    *,
    callsign: str | None = None,
    recipient: str | None = None,
    position: str | None = None,
    preview_time: datetime | None = None,
) -> TemplatePreview:
    """Render one template without performing database, network or send actions."""
    placeholders = extract_placeholders(template_text)
    fixed_time = _validate_preview_time(preview_time)
    replacements: dict[str, str] = {
        "DATO": fixed_time.strftime("%Y-%m-%d"),
        "TID": fixed_time.strftime("%H:%M"),
    }
    if "KALLESIGNAL" in placeholders:
        replacements["KALLESIGNAL"] = _normalize_single_line(
            callsign,
            field_name="Kallesignal",
            max_length=_MAX_CALLSIGN_LENGTH,
        )
    if "MOTTAKER" in placeholders:
        replacements["MOTTAKER"] = _normalize_single_line(
            recipient,
            field_name="Mottaker",
            max_length=_MAX_RECIPIENT_LENGTH,
        )
    if "POSISJON" in placeholders:
        replacements["POSISJON"] = _normalize_single_line(
            position,
            field_name="Posisjon",
            max_length=64,
        )

    rendered = template_text
    for placeholder in placeholders:
        rendered = rendered.replace(
            "{" + placeholder + "}",
            replacements[placeholder],
        )
    return TemplatePreview(
        text=rendered,
        placeholders=placeholders,
        preview_time=fixed_time,
    )
