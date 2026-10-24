#!/usr/bin/env python3
"""Delimited export helpers shared by the GuToChat GUI and tests."""
from __future__ import annotations

import csv
from datetime import date, datetime, time as dt_time
from pathlib import Path
from typing import Any, Iterable, Sequence

FORMULA_PREFIXES = ("=", "+", "-", "@")


def local_timezone():
    return datetime.now().astimezone().tzinfo


def parse_datetime_input(value: str, *, end_of_day: bool = False) -> datetime | None:
    """Parse ISO or Norwegian date/time input in the local timezone.

    Accepted examples: ``2026-07-01``, ``2026-07-01 12:30``,
    ``01.07.2026`` and ``01.07.2026 12:30:15``. A date-only upper
    bound includes the whole day.
    """
    text = str(value or "").strip()
    if not text:
        return None

    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass

    if parsed is None:
        formats = (
            "%d.%m.%Y %H:%M:%S",
            "%d.%m.%Y %H:%M",
            "%d.%m.%Y",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d",
        )
        for fmt in formats:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        raise ValueError(
            "Ugyldig dato/tid. Bruk for eksempel 2026-07-01 12:30 "
            "eller 01.07.2026 12:30."
        )

    date_only = not any(separator in text.strip() for separator in (":", "T"))
    if date_only:
        chosen_time = dt_time.max if end_of_day else dt_time.min
        parsed = datetime.combine(parsed.date(), chosen_time)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=local_timezone())
    return parsed.astimezone()


def value_as_datetime(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, dt_time.min)
    elif isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(float(value)).astimezone()
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            try:
                parsed = datetime.fromtimestamp(float(text)).astimezone()
            except (ValueError, OverflowError, OSError):
                return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=local_timezone())
    return parsed.astimezone()


def iso_timestamp(value: Any) -> str:
    parsed = value_as_datetime(value)
    if parsed is None:
        return "" if value in (None, "") else str(value)
    return parsed.isoformat(timespec="seconds")


def in_inclusive_range(
    value: Any,
    start: datetime | None,
    end: datetime | None,
) -> bool:
    parsed = value_as_datetime(value)
    if parsed is None:
        return start is None and end is None
    if start is not None and parsed < start:
        return False
    if end is not None and parsed > end:
        return False
    return True


def spreadsheet_safe(value: Any) -> Any:
    """Prevent formula execution while preserving numeric cell types."""
    if not isinstance(value, str):
        return value
    stripped = value.lstrip()
    if stripped.startswith(FORMULA_PREFIXES):
        prefix_len = len(value) - len(stripped)
        return value[:prefix_len] + "'" + stripped
    return value


def write_delimited(
    path: Path,
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    *,
    delimiter: str,
) -> int:
    if delimiter not in {",", "\t"}:
        raise ValueError("Bare CSV (komma) og TSV (tabulator) støttes")
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    # utf-8-sig writes a BOM that helps Excel recognize Norwegian UTF-8 text.
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(
            handle,
            delimiter=delimiter,
            quotechar='"',
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\n",
        )
        writer.writerow([spreadsheet_safe(str(item)) for item in headers])
        for row in rows:
            writer.writerow([spreadsheet_safe(item) for item in row])
            count += 1
    return count
