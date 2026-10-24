#!/usr/bin/env python3
"""Local, durable emergency-message templates stored in the shared SQLite DB."""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from template_placeholders import extract_placeholders


TEMPLATE_FORMAT = "lorachat-emergency-templates"
TEMPLATE_FORMAT_VERSION = 2
TEMPLATE_SEVERITIES = (
    "information",
    "status",
    "urgent",
    "emergency",
)
TEMPLATE_CATEGORIES = (
    "Nød",
    "Status",
    "Møtepunkt",
    "Forsyning",
    "Teknisk",
    "Egendefinert",
)
MAX_NAME_LENGTH = 80
MAX_TEXT_LENGTH = 4000
_UNSET = object()


class TemplateConflictError(ValueError):
    """Raised when an import or create would overwrite a template silently."""

    def __init__(self, template_ids: Iterable[str]) -> None:
        self.template_ids = tuple(sorted({str(value) for value in template_ids}))
        joined = ", ".join(self.template_ids)
        super().__init__(f"Mal-ID finnes allerede: {joined}")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _default_id(name: str) -> str:
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"https://lorachat.local/emergency-template/{name}",
        )
    )


DEFAULT_TEMPLATES: tuple[dict[str, Any], ...] = (
    {
        "id": _default_id("alt-i-orden"),
        "name": "Alt i orden",
        "category": "Status",
        "text": "Jeg er OK. Ingen hjelp nødvendig.",
        "sort_order": 10,
        "requires_confirmation": False,
    },
    {
        "id": _default_id("hjemme"),
        "name": "Hjemme",
        "category": "Status",
        "text": "Jeg er hjemme.",
        "sort_order": 20,
        "requires_confirmation": False,
    },
    {
        "id": _default_id("trenger-hjelp"),
        "name": "Trenger hjelp",
        "category": "Nød",
        "text": "Jeg trenger hjelp. Kontakt meg så snart som mulig.",
        "sort_order": 30,
        "requires_confirmation": True,
    },
    {
        "id": _default_id("avtalt-sted"),
        "name": "Møt på avtalt sted",
        "category": "Møtepunkt",
        "text": "Møt på avtalt sted.",
        "sort_order": 40,
        "requires_confirmation": False,
    },
    {
        "id": _default_id("strombrudd"),
        "name": "Strømbrudd",
        "category": "Teknisk",
        "text": "Strømmen er borte her.",
        "sort_order": 50,
        "requires_confirmation": False,
    },
    {
        "id": _default_id("lite-batteri"),
        "name": "Lite batteri",
        "category": "Teknisk",
        "text": "Jeg har lite batteri. Svar kort.",
        "sort_order": 60,
        "requires_confirmation": False,
    },
    {
        "id": _default_id("send-posisjon"),
        "name": "Be om posisjon",
        "category": "Status",
        "text": "Kan du sende din posisjon?",
        "sort_order": 70,
        "requires_confirmation": False,
    },
)


class EmergencyTemplateStore:
    """CRUD, ordering and versioned import/export for local message templates."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=5000")
        return con

    def _init_db(self) -> None:
        with self._connect() as con:
            existed = (
                con.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'emergency_templates'"
                ).fetchone()
                is not None
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS emergency_templates (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    text TEXT NOT NULL,
                    sort_order INTEGER NOT NULL DEFAULT 0,
                    requires_confirmation INTEGER NOT NULL DEFAULT 0,
                    severity TEXT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    CHECK (requires_confirmation IN (0, 1)),
                    CHECK (
                        severity IS NULL OR severity IN (
                            'information', 'status', 'urgent', 'emergency'
                        )
                    )
                )
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_emergency_templates_order "
                "ON emergency_templates(sort_order, name, id)"
            )
            columns = {
                str(row[1])
                for row in con.execute("PRAGMA table_info(emergency_templates)")
            }
            if "severity" not in columns:
                con.execute(
                    "ALTER TABLE emergency_templates "
                    "ADD COLUMN severity TEXT NULL"
                )
            invalid_severities = con.execute(
                "SELECT DISTINCT severity FROM emergency_templates "
                "WHERE severity IS NOT NULL "
                "AND severity NOT IN (?, ?, ?, ?)",
                TEMPLATE_SEVERITIES,
            ).fetchall()
            if invalid_severities:
                values = ", ".join(str(row[0]) for row in invalid_severities)
                raise ValueError(f"Ugyldig alvorlighetsgrad i databasen: {values}")
            if not existed:
                stamp = now_iso()
                con.executemany(
                    """
                    INSERT OR IGNORE INTO emergency_templates(
                        id, name, category, text, sort_order,
                        requires_confirmation, severity, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            str(item["id"]),
                            str(item["name"]),
                            str(item["category"]),
                            str(item["text"]),
                            int(item["sort_order"]),
                            int(bool(item["requires_confirmation"])),
                            None,
                            stamp,
                            stamp,
                        )
                        for item in DEFAULT_TEMPLATES
                    ],
                )

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "category": str(row["category"]),
            "text": str(row["text"]),
            "sort_order": int(row["sort_order"]),
            "requires_confirmation": bool(row["requires_confirmation"]),
            "severity": (
                None if row["severity"] is None else str(row["severity"])
            ),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _normalize_id(value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Mal-ID må være en UUID")
        try:
            return str(uuid.UUID(value.strip()))
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"Ugyldig mal-ID: {value}") from exc

    @staticmethod
    def _normalize_name(value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("Malnavn må være tekst")
        name = value.strip()
        if not name:
            raise ValueError("Malnavn kan ikke være tomt")
        if "\n" in name or "\r" in name:
            raise ValueError("Malnavn kan ikke inneholde linjeskift")
        if len(name) > MAX_NAME_LENGTH:
            raise ValueError(f"Malnavn kan ha maksimalt {MAX_NAME_LENGTH} tegn")
        return name

    @staticmethod
    def _normalize_category(value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("Kategori må være tekst")
        category = value.strip()
        if category not in TEMPLATE_CATEGORIES:
            raise ValueError(f"Ukjent kategori: {category or '(tom)'}")
        return category

    @staticmethod
    def _normalize_text(value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("Meldingstekst må være tekst")
        if not value.strip():
            raise ValueError("Meldingstekst kan ikke være tom")
        if len(value) > MAX_TEXT_LENGTH:
            raise ValueError(
                f"Meldingstekst kan ha maksimalt {MAX_TEXT_LENGTH} tegn"
            )
        extract_placeholders(value)
        return value

    @staticmethod
    def _normalize_confirmation(value: Any) -> bool:
        if not isinstance(value, bool):
            raise ValueError("Bekreftelsesverdi må være sann eller usann")
        return value

    @staticmethod
    def _normalize_severity(value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Alvorlighetsgrad må være tekst eller null")
        severity = value.strip()
        if severity not in TEMPLATE_SEVERITIES:
            raise ValueError(
                f"Ukjent alvorlighetsgrad: {severity or '(tom)'}"
            )
        return severity

    @staticmethod
    def _normalize_sort_order(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("Sorteringsverdi må være et heltall")
        if not -1_000_000_000 <= value <= 1_000_000_000:
            raise ValueError("Sorteringsverdi er utenfor tillatt område")
        return value

    @staticmethod
    def _normalize_timestamp(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} mangler tidsstempel")
        stamp = value.strip()
        try:
            parsed = datetime.fromisoformat(stamp)
        except ValueError as exc:
            raise ValueError(f"{field} har ugyldig ISO-8601-tidsstempel") from exc
        if parsed.tzinfo is None:
            raise ValueError(f"{field} må inneholde tidssone")
        return stamp

    def _normalize_import_template(
        self, raw: Any, *, index: int, format_version: int
    ) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise ValueError(f"Mal {index} er ikke et JSON-objekt")
        created_at = self._normalize_timestamp(raw.get("created_at"), "created_at")
        updated_at = self._normalize_timestamp(raw.get("updated_at"), "updated_at")
        return {
            "id": self._normalize_id(raw.get("id")),
            "name": self._normalize_name(raw.get("name")),
            "category": self._normalize_category(raw.get("category")),
            "text": self._normalize_text(raw.get("text")),
            "sort_order": self._normalize_sort_order(raw.get("sort_order")),
            "requires_confirmation": self._normalize_confirmation(
                raw.get("requires_confirmation")
            ),
            "severity": self._normalize_severity(
                raw.get("severity") if format_version >= 2 else None
            ),
            "created_at": created_at,
            "updated_at": updated_at,
        }

    def list_templates(self, category: str | None = None) -> list[dict[str, Any]]:
        parameters: tuple[Any, ...] = ()
        where = ""
        if category is not None:
            where = " WHERE category = ?"
            parameters = (self._normalize_category(category),)
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM emergency_templates"
                + where
                + " ORDER BY sort_order, name COLLATE NOCASE, id",
                parameters,
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_template(self, template_id: str) -> dict[str, Any] | None:
        normalized_id = self._normalize_id(template_id)
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM emergency_templates WHERE id = ?",
                (normalized_id,),
            ).fetchone()
        return self._row_to_dict(row) if row is not None else None

    @staticmethod
    def _next_sort_order(con: sqlite3.Connection) -> int:
        row = con.execute(
            "SELECT COALESCE(MAX(sort_order), 0) + 10 FROM emergency_templates"
        ).fetchone()
        return int(row[0])

    def create_template(
        self,
        *,
        name: str,
        category: str,
        text: str,
        requires_confirmation: bool = False,
        severity: str | None = None,
        template_id: str | None = None,
        sort_order: int | None = None,
    ) -> dict[str, Any]:
        normalized_id = self._normalize_id(template_id or str(uuid.uuid4()))
        normalized_name = self._normalize_name(name)
        normalized_category = self._normalize_category(category)
        normalized_text = self._normalize_text(text)
        normalized_confirmation = self._normalize_confirmation(requires_confirmation)
        normalized_severity = self._normalize_severity(severity)
        stamp = now_iso()
        with self._connect() as con:
            order = (
                self._next_sort_order(con)
                if sort_order is None
                else self._normalize_sort_order(sort_order)
            )
            try:
                con.execute(
                    """
                    INSERT INTO emergency_templates(
                        id, name, category, text, sort_order,
                        requires_confirmation, severity, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_id,
                        normalized_name,
                        normalized_category,
                        normalized_text,
                        order,
                        int(normalized_confirmation),
                        normalized_severity,
                        stamp,
                        stamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise TemplateConflictError([normalized_id]) from exc
        result = self.get_template(normalized_id)
        assert result is not None
        return result

    def update_template(
        self,
        template_id: str,
        *,
        name: str | None = None,
        category: str | None = None,
        text: str | None = None,
        requires_confirmation: bool | None = None,
        severity: str | None | object = _UNSET,
        sort_order: int | None = None,
    ) -> dict[str, Any]:
        normalized_id = self._normalize_id(template_id)
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM emergency_templates WHERE id = ?",
                (normalized_id,),
            ).fetchone()
            if row is None:
                raise KeyError(normalized_id)
            current = self._row_to_dict(row)
            updated = {
                "name": current["name"] if name is None else self._normalize_name(name),
                "category": (
                    current["category"]
                    if category is None
                    else self._normalize_category(category)
                ),
                "text": current["text"] if text is None else self._normalize_text(text),
                "requires_confirmation": (
                    current["requires_confirmation"]
                    if requires_confirmation is None
                    else self._normalize_confirmation(requires_confirmation)
                ),
                "severity": (
                    current["severity"]
                    if severity is _UNSET
                    else self._normalize_severity(severity)
                ),
                "sort_order": (
                    current["sort_order"]
                    if sort_order is None
                    else self._normalize_sort_order(sort_order)
                ),
            }
            stamp = now_iso()
            con.execute(
                """
                UPDATE emergency_templates
                   SET name = ?, category = ?, text = ?, sort_order = ?,
                       requires_confirmation = ?, severity = ?, updated_at = ?
                 WHERE id = ?
                """,
                (
                    updated["name"],
                    updated["category"],
                    updated["text"],
                    updated["sort_order"],
                    int(bool(updated["requires_confirmation"])),
                    updated["severity"],
                    stamp,
                    normalized_id,
                ),
            )
        result = self.get_template(normalized_id)
        assert result is not None
        return result

    def copy_template(
        self, template_id: str, *, name: str | None = None
    ) -> dict[str, Any]:
        source = self.get_template(template_id)
        if source is None:
            raise KeyError(self._normalize_id(template_id))
        copy_name = name if name is not None else self._copy_name(str(source["name"]))
        return self.create_template(
            name=copy_name,
            category=str(source["category"]),
            text=str(source["text"]),
            requires_confirmation=bool(source["requires_confirmation"]),
            severity=source["severity"],
        )

    @staticmethod
    def _copy_name(name: str) -> str:
        suffix = " (kopi)"
        base = name[: MAX_NAME_LENGTH - len(suffix)].rstrip()
        return base + suffix

    def delete_template(self, template_id: str) -> bool:
        normalized_id = self._normalize_id(template_id)
        with self._connect() as con:
            cursor = con.execute(
                "DELETE FROM emergency_templates WHERE id = ?",
                (normalized_id,),
            )
        return cursor.rowcount > 0

    def move_template(self, template_id: str, direction: int) -> bool:
        """Move one position; direction must be -1 (up) or 1 (down)."""
        normalized_id = self._normalize_id(template_id)
        if direction not in (-1, 1):
            raise ValueError("Retning må være -1 eller 1")
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            rows = con.execute(
                "SELECT id, sort_order FROM emergency_templates "
                "ORDER BY sort_order, name COLLATE NOCASE, id"
            ).fetchall()
            ids = [str(row["id"]) for row in rows]
            if normalized_id not in ids:
                raise KeyError(normalized_id)
            current_index = ids.index(normalized_id)
            target_index = current_index + direction
            if target_index < 0 or target_index >= len(ids):
                return False
            ids[current_index], ids[target_index] = ids[target_index], ids[current_index]
            stamp = now_iso()
            for index, item_id in enumerate(ids, start=1):
                new_order = index * 10
                con.execute(
                    "UPDATE emergency_templates SET sort_order = ?, updated_at = ? "
                    "WHERE id = ? AND sort_order != ?",
                    (new_order, stamp, item_id, new_order),
                )
        return True

    def export_payload(self) -> dict[str, Any]:
        return {
            "format": TEMPLATE_FORMAT,
            "version": TEMPLATE_FORMAT_VERSION,
            "exported_at": now_iso(),
            "templates": self.list_templates(),
        }

    def export_file(self, path: Path) -> int:
        payload = self.export_payload()
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
        return len(payload["templates"])

    def import_payload(
        self,
        payload: dict[str, Any],
        *,
        conflict_mode: str = "error",
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("Malfilen må inneholde et JSON-objekt")
        if payload.get("format") != TEMPLATE_FORMAT:
            raise ValueError("Filen er ikke en GuToChat / LoRa Chat-malfil")
        try:
            format_version = int(payload.get("version", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("Malfilen har en ukjent formatversjon") from exc
        if format_version not in {1, TEMPLATE_FORMAT_VERSION}:
            raise ValueError("Malfilen har en ukjent formatversjon")
        raw_templates = payload.get("templates")
        if not isinstance(raw_templates, list):
            raise ValueError("Malfilen mangler mallisten")
        if conflict_mode not in {"error", "skip", "copy", "replace"}:
            raise ValueError("Ukjent konflikthåndtering")

        # Validate every row before opening a write transaction. A malformed
        # file therefore cannot leave a partially imported template set.
        normalized = [
            self._normalize_import_template(
                raw, index=index, format_version=format_version
            )
            for index, raw in enumerate(raw_templates, start=1)
        ]
        normalized_ids = [str(item["id"]) for item in normalized]
        duplicate_ids = {
            template_id
            for template_id in normalized_ids
            if normalized_ids.count(template_id) > 1
        }
        if duplicate_ids:
            raise ValueError(
                "Malfilen inneholder dupliserte ID-er: "
                + ", ".join(sorted(duplicate_ids))
            )

        report: dict[str, Any] = {
            "total": len(normalized),
            "imported": 0,
            "skipped": 0,
            "copied": 0,
            "replaced": 0,
            "conflicts": [],
        }
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            existing_ids = {
                str(row[0])
                for row in con.execute("SELECT id FROM emergency_templates")
            }
            conflicts = sorted(existing_ids.intersection(normalized_ids))
            report["conflicts"] = conflicts
            if conflicts and conflict_mode == "error":
                raise TemplateConflictError(conflicts)

            imported_max_order = max(
                (int(item["sort_order"]) for item in normalized),
                default=0,
            )
            next_order = max(
                self._next_sort_order(con),
                imported_max_order + 10,
            )
            for item in normalized:
                template_id = str(item["id"])
                copied_conflict = False
                if template_id in existing_ids:
                    if conflict_mode == "skip":
                        report["skipped"] += 1
                        continue
                    if conflict_mode == "copy":
                        template_id = str(uuid.uuid4())
                        item = dict(item)
                        item["id"] = template_id
                        item["name"] = self._copy_name(str(item["name"]))
                        item["sort_order"] = next_order
                        item["created_at"] = now_iso()
                        item["updated_at"] = item["created_at"]
                        next_order += 10
                        report["copied"] += 1
                        copied_conflict = True
                    elif conflict_mode == "replace":
                        con.execute(
                            """
                            UPDATE emergency_templates
                               SET name = ?, category = ?, text = ?, sort_order = ?,
                                   requires_confirmation = ?, severity = ?,
                                   created_at = ?, updated_at = ?
                             WHERE id = ?
                            """,
                            (
                                item["name"],
                                item["category"],
                                item["text"],
                                item["sort_order"],
                                int(bool(item["requires_confirmation"])),
                                item["severity"],
                                item["created_at"],
                                item["updated_at"],
                                template_id,
                            ),
                        )
                        report["replaced"] += 1
                        continue
                con.execute(
                    """
                    INSERT INTO emergency_templates(
                        id, name, category, text, sort_order,
                        requires_confirmation, severity, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        template_id,
                        item["name"],
                        item["category"],
                        item["text"],
                        item["sort_order"],
                        int(bool(item["requires_confirmation"])),
                        item["severity"],
                        item["created_at"],
                        item["updated_at"],
                    ),
                )
                if not copied_conflict:
                    report["imported"] += 1
                existing_ids.add(template_id)
        return report

    def import_file(
        self,
        path: Path,
        *,
        conflict_mode: str = "error",
    ) -> dict[str, Any]:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Malfilen må inneholde et JSON-objekt")
        return self.import_payload(raw, conflict_mode=conflict_mode)
