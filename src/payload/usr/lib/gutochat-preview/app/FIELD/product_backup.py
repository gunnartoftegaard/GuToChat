#!/usr/bin/env python3
"""Privacy-minimized GuToChat product-backup creator.

This module is deliberately backup-only. It reads local files and SQLite data,
creates a new archive atomically, and never modifies source configuration,
databases, maps, services, radios, or GPS state. It contains no restore path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sqlite3
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from emergency_templates import TEMPLATE_FORMAT, TEMPLATE_FORMAT_VERSION
from offline_map import (
    MAX_DISCOVERED_MAP_FILES,
    read_map_package,
    resolve_database_path,
    resolve_offline_map_directory,
)
from roles import infer_role_from_config


BACKUP_FORMAT = "gutochat-product-backup"
BACKUP_FORMAT_VERSION = 1
BACKUP_PROFILE = "standard-minimal"
SCHEMA_FORMAT = "gutochat-database-schema"
SCHEMA_FORMAT_VERSION = 1
MAP_INVENTORY_FORMAT = "gutochat-map-inventory"
MAP_INVENTORY_FORMAT_VERSION = 1
PREFERENCES_FORMAT = "gutochat-preferences"
PREFERENCES_FORMAT_VERSION = 1
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
MAX_JSON_SOURCE_BYTES = 1024 * 1024
MAX_EMERGENCY_TEMPLATES = 10_000
SAFE_CONFIG_KEYS = frozenset(
    {
        "ui_message_limit",
        "export_message_max_rows",
        "export_position_max_rows",
        "node_stale_hours",
    }
)
EXCLUDED_DOMAINS = (
    "messages",
    "contacts",
    "positions",
    "node_identity",
    "station_identity",
    "radio_configuration",
    "secrets",
    "raw_payloads",
    "runtime_queues",
    "sync_state",
    "map_files",
    "installer_backups",
    "export_files",
)


class BackupError(ValueError):
    """Raised when a safe product backup cannot be created."""


@dataclass(frozen=True)
class BackupResult:
    archive_path: Path
    sidecar_path: Path
    archive_sha256: str
    manifest: dict[str, Any]


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _validate_iso_timestamp(value: str) -> str:
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise BackupError("created_at must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise BackupError("created_at must include a timezone")
    return text


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise BackupError("backup data is not strict JSON") from exc
    return (text + "\n").encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file(path: Path, *, required: bool = True) -> bool:
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        if required:
            raise BackupError(f"required source file is missing: {path.name}")
        return False
    except OSError as exc:
        raise BackupError(f"source file cannot be inspected: {path.name}") from exc
    if not stat.S_ISREG(mode):
        if required:
            raise BackupError(f"source is not a regular file: {path.name}")
        return False
    return True


def _read_json_object(path: Path, *, required: bool) -> dict[str, Any]:
    if not _regular_file(path, required=required):
        return {}
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise BackupError(f"JSON source cannot be inspected: {path.name}") from exc
    if size > MAX_JSON_SOURCE_BYTES:
        raise BackupError(f"JSON source is too large: {path.name}")

    def reject_nonstandard_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant: {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=reject_nonstandard_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise BackupError(f"invalid JSON source: {path.name}") from exc
    if not isinstance(value, dict):
        raise BackupError(f"JSON source must contain an object: {path.name}")
    return value


def _resolve_path(value: Any, *, base: Path | None = None) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute() and base is not None:
        path = base / path
    return path


def _open_database_read_only(path: Path) -> sqlite3.Connection:
    _regular_file(path)
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA query_only=ON")
        return con
    except sqlite3.Error as exc:
        raise BackupError("database cannot be opened read-only") from exc


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _safe_scalar(value: Any) -> bool:
    if isinstance(value, float):
        return math.isfinite(value)
    return value is None or isinstance(value, (bool, int, str))


def _read_preferences(
    config: Mapping[str, Any],
    ui_state_path: Path,
    database_path: Path,
) -> tuple[dict[str, Any], dict[str, int]]:
    runtime: dict[str, Any] = {}
    for key in sorted(SAFE_CONFIG_KEYS):
        value = config.get(key)
        if _safe_scalar(value):
            if isinstance(value, str) and len(value) > 128:
                continue
            if value is not None:
                runtime[key] = value

    ui_raw = _read_json_object(ui_state_path, required=False)
    ui: dict[str, Any] = {}
    message_view = ui_raw.get("message_view")
    if message_view in {"Tabellvisning", "Samtalevisning"}:
        ui["message_view"] = message_view
    favorites_only = ui_raw.get("favorite_recipients_only")
    if isinstance(favorites_only, bool):
        ui["favorite_recipients_only"] = favorites_only

    position: dict[str, Any] = {}
    with _open_database_read_only(database_path) as con:
        if _table_exists(con, "position_settings"):
            rows = con.execute(
                "SELECT key, value FROM position_settings "
                "WHERE key IN ('storage_enabled', 'stale_minutes') ORDER BY key"
            ).fetchall()
            values = {str(row["key"]): str(row["value"]) for row in rows}
            if "storage_enabled" in values:
                position["storage_enabled"] = values["storage_enabled"].strip() not in {
                    "0",
                    "false",
                    "False",
                }
            if "stale_minutes" in values:
                try:
                    stale = int(values["stale_minutes"])
                except ValueError:
                    stale = 30
                position["stale_minutes"] = max(1, min(365 * 24 * 60, stale))

    payload = {
        "format": PREFERENCES_FORMAT,
        "version": PREFERENCES_FORMAT_VERSION,
        "runtime": runtime,
        "ui": ui,
        "position_privacy": position,
    }
    counts = {
        "runtime_preferences": len(runtime),
        "ui_preferences": len(ui),
        "position_privacy_preferences": len(position),
    }
    return payload, counts


def _read_emergency_templates(
    database_path: Path,
    created_at: str,
) -> tuple[dict[str, Any], int]:
    templates: list[dict[str, Any]] = []
    with _open_database_read_only(database_path) as con:
        if _table_exists(con, "emergency_templates"):
            columns = {
                str(row["name"])
                for row in con.execute("PRAGMA table_info(emergency_templates)")
            }
            required = {
                "id",
                "name",
                "category",
                "text",
                "sort_order",
                "requires_confirmation",
                "created_at",
                "updated_at",
            }
            if not required.issubset(columns):
                raise BackupError("emergency_templates schema is incomplete")
            severity_sql = "severity" if "severity" in columns else "NULL AS severity"
            rows = con.execute(
                "SELECT id, name, category, text, sort_order, "
                "requires_confirmation, "
                + severity_sql
                + ", created_at, updated_at FROM emergency_templates "
                "ORDER BY sort_order, name COLLATE NOCASE, id "
                "LIMIT ?",
                (MAX_EMERGENCY_TEMPLATES + 1,),
            ).fetchall()
            if len(rows) > MAX_EMERGENCY_TEMPLATES:
                raise BackupError("too many emergency templates for MVP backup")
            for row in rows:
                templates.append(
                    {
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
                )
    return {
        "format": TEMPLATE_FORMAT,
        "version": TEMPLATE_FORMAT_VERSION,
        "exported_at": created_at,
        "templates": templates,
    }, len(templates)


def _normalize_sql(value: Any) -> str:
    return " ".join(str(value or "").split())


def _read_database_schema(database_path: Path) -> tuple[dict[str, Any], int]:
    objects: list[dict[str, Any]] = []
    with _open_database_read_only(database_path) as con:
        rows = con.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' "
            "AND type IN ('table', 'index', 'view', 'trigger') "
            "ORDER BY type, name"
        ).fetchall()
        for row in rows:
            normalized_sql = _normalize_sql(row["sql"])
            item: dict[str, Any] = {
                "type": str(row["type"]),
                "name": str(row["name"]),
                "table": str(row["tbl_name"]),
                # Raw CREATE/trigger SQL is intentionally omitted because a
                # user-defined object could contain sensitive string literals.
                "sql_sha256": _sha256_bytes(normalized_sql.encode("utf-8")),
            }
            if str(row["type"]) == "table":
                columns = con.execute(
                    'SELECT cid, name, type, "notnull" AS not_null_flag, '
                    'dflt_value, pk, hidden FROM pragma_table_xinfo(?) ORDER BY cid',
                    (str(row["name"]),),
                ).fetchall()
                item["columns"] = [
                    {
                        "position": int(column["cid"]),
                        "name": str(column["name"]),
                        "declared_type": str(column["type"] or ""),
                        "not_null": bool(column["not_null_flag"]),
                        "primary_key_position": int(column["pk"]),
                        "hidden": int(column["hidden"]),
                        "has_default": column["dflt_value"] is not None,
                    }
                    for column in columns
                ]
            objects.append(item)
    canonical = _canonical_json_bytes(objects)
    return {
        "format": SCHEMA_FORMAT,
        "version": SCHEMA_FORMAT_VERSION,
        "identity_algorithm": "sha256-canonical-json-v1",
        "identity_sha256": _sha256_bytes(canonical),
        "raw_sql_included": False,
        "objects": objects,
    }, len(objects)


def _iter_map_files(directory: Path) -> tuple[list[Path], int]:
    try:
        root_mode = directory.lstat().st_mode
    except FileNotFoundError:
        return [], 0
    except OSError as exc:
        raise BackupError("map directory cannot be inspected") from exc
    if not stat.S_ISDIR(root_mode) or directory.is_symlink():
        return [], 0
    result: list[Path] = []
    discovered = 0
    for current, directory_names, file_names in os.walk(directory, followlinks=False):
        current_path = Path(current)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if not (current_path / name).is_symlink()
        )
        for name in sorted(file_names):
            path = current_path / name
            if path.suffix.casefold() != ".mbtiles" or path.is_symlink():
                continue
            try:
                mode = path.lstat().st_mode
            except OSError:
                continue
            if stat.S_ISREG(mode):
                discovered += 1
                if len(result) < MAX_DISCOVERED_MAP_FILES:
                    result.append(path)
    return result, discovered


def _map_entry(path: Path, relative_path: str, source: str) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "source": source,
        "relative_path": relative_path.replace(os.sep, "/"),
        "bytes": int(path.stat().st_size),
        "sha256": _sha256_file(path),
    }
    try:
        package = read_map_package(path)
    except (OSError, sqlite3.Error, ValueError):
        entry.update(
            {
                "validation_state": "invalid",
                "validation_error": "invalid_metadata_or_structure",
            }
        )
        return entry
    entry.update(
        {
            "validation_state": "valid",
            "name": package.name,
            "bounds": list(package.bounds),
            "minzoom": package.min_zoom,
            "maxzoom": package.max_zoom,
            "format": package.image_format,
            "attribution": package.attribution,
            "gutochat_type": package.package_type,
            "gutochat_priority": package.priority,
        }
    )
    return entry


def _read_map_inventory(
    config: Mapping[str, Any],
    map_directory: Path,
) -> tuple[dict[str, Any], dict[str, int]]:
    entries: list[dict[str, Any]] = []
    seen: set[Path] = set()
    map_files, discovered_package_files = _iter_map_files(map_directory)
    for path in map_files:
        resolved = path.resolve()
        seen.add(resolved)
        entries.append(
            _map_entry(path, str(path.relative_to(map_directory)), "package_directory")
        )

    legacy_raw = str(config.get("offline_map_path") or "").strip()
    if legacy_raw:
        legacy = Path(legacy_raw).expanduser()
        try:
            regular = _regular_file(legacy, required=False)
        except BackupError:
            regular = False
        if regular and legacy.suffix.casefold() == ".mbtiles" and legacy.resolve() not in seen:
            entries.append(_map_entry(legacy, legacy.name, "legacy_path"))

    entries.sort(key=lambda item: (str(item["source"]), str(item["relative_path"]).casefold()))
    valid = sum(1 for item in entries if item["validation_state"] == "valid")
    invalid = len(entries) - valid
    omitted_package_files = max(0, discovered_package_files - len(map_files))
    truncated = omitted_package_files > 0
    payload = {
        "format": MAP_INVENTORY_FORMAT,
        "version": MAP_INVENTORY_FORMAT_VERSION,
        "map_files_included": False,
        "truncated": truncated,
        "discovery_limit": MAX_DISCOVERED_MAP_FILES,
        "discovered_package_files": discovered_package_files,
        "omitted_package_files": omitted_package_files,
        "entries": entries,
    }
    return payload, {
        "map_entries": len(entries),
        "valid_maps": valid,
        "invalid_maps": invalid,
        "map_entries_omitted": omitted_package_files,
    }


def _zip_member(name: str, data: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(filename=name, date_time=ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o600 << 16
    return info, data


def _package_contents(payloads: Mapping[str, bytes]) -> bytes:
    lines = [f"{_sha256_bytes(payloads[name])}  {name}" for name in sorted(payloads)]
    return ("\n".join(lines) + "\n").encode("ascii")


def _write_atomic_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        os.chmod(path, mode)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _prepare_atomic_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> Path:
    """Write and fsync a sibling temp file without changing the final target."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        return temporary
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _target_state(path: Path) -> bool:
    """Return whether a regular target exists; reject unsafe target types."""
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(mode):
        raise OSError(f"backup target is not a regular file: {path.name}")
    return True


def _unused_sibling(path: Path, suffix: str) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=suffix,
        dir=path.parent,
    )
    os.close(descriptor)
    candidate = Path(name)
    candidate.unlink()
    return candidate


def _write_atomic_pair(
    first_path: Path,
    first_data: bytes,
    second_path: Path,
    second_data: bytes,
    *,
    mode: int = 0o600,
) -> None:
    """Replace two sibling files as one exception-atomic backup pair.

    Both new files are fully written and fsynced before either final path is
    touched. If commit then fails, any previous complete pair is restored and
    a fresh partial pair is removed.
    """
    if first_path.parent != second_path.parent:
        raise BackupError("backup archive and sidecar must share one directory")
    first_path.parent.mkdir(parents=True, exist_ok=True)
    first_exists = _target_state(first_path)
    second_exists = _target_state(second_path)
    if first_exists != second_exists:
        raise BackupError("existing backup archive/sidecar pair is incomplete")

    first_temporary: Path | None = None
    second_temporary: Path | None = None
    first_previous: Path | None = None
    second_previous: Path | None = None
    first_committed = False
    second_committed = False
    try:
        first_temporary = _prepare_atomic_bytes(first_path, first_data, mode=mode)
        second_temporary = _prepare_atomic_bytes(second_path, second_data, mode=mode)

        if first_exists:
            first_previous = _unused_sibling(first_path, ".previous")
            second_previous = _unused_sibling(second_path, ".previous")
            os.replace(first_path, first_previous)
            try:
                os.replace(second_path, second_previous)
            except Exception:
                os.replace(first_previous, first_path)
                first_previous = None
                raise

        os.replace(first_temporary, first_path)
        first_temporary = None
        first_committed = True
        os.replace(second_temporary, second_path)
        second_temporary = None
        second_committed = True
        os.chmod(first_path, mode)
        os.chmod(second_path, mode)
    except Exception:
        if second_committed:
            try:
                second_path.unlink()
            except FileNotFoundError:
                pass
        if first_committed:
            try:
                first_path.unlink()
            except FileNotFoundError:
                pass
        if first_previous is not None and first_previous.exists():
            os.replace(first_previous, first_path)
            first_previous = None
        if second_previous is not None and second_previous.exists():
            os.replace(second_previous, second_path)
            second_previous = None
        raise
    finally:
        for temporary in (
            first_temporary,
            second_temporary,
            first_previous,
            second_previous,
        ):
            if temporary is None:
                continue
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _build_archive_bytes(payloads: Mapping[str, bytes]) -> bytes:
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as buffer:
        with zipfile.ZipFile(buffer, "w") as archive:
            for name in sorted(payloads):
                info, data = _zip_member(name, payloads[name])
                archive.writestr(info, data)
        buffer.seek(0)
        return buffer.read()


def create_product_backup(
    config_path: Path,
    output_path: Path,
    *,
    database_path: Path | None = None,
    ui_state_path: Path | None = None,
    map_directory: Path | None = None,
    product_version: str | None = None,
    created_at: str | None = None,
) -> BackupResult:
    """Create one privacy-minimized, backup-only product archive."""
    config_path = Path(config_path).expanduser()
    config = _read_json_object(config_path, required=True)
    source_role = infer_role_from_config(dict(config))
    stamp = _validate_iso_timestamp(created_at) if created_at else _now_iso()
    version = str(product_version or config.get("app_version") or "unknown").strip()
    if not version or len(version) > 128 or "\n" in version or "\r" in version:
        raise BackupError("invalid product version")

    config_directory = config_path.parent
    if database_path is None:
        database_path = resolve_database_path(config)
    database_path = _resolve_path(database_path, base=config_directory)
    if ui_state_path is None:
        raw_ui = config.get("ui_state_file")
        if raw_ui:
            ui_state_path = _resolve_path(raw_ui, base=config_directory)
        else:
            contacts_raw = config.get("contacts_file")
            contacts_path = (
                _resolve_path(contacts_raw, base=config_directory)
                if contacts_raw
                else config_directory / "contacts.json"
            )
            ui_state_path = contacts_path.with_name("ui-state.json")
    else:
        ui_state_path = _resolve_path(ui_state_path, base=config_directory)
    if map_directory is None:
        map_directory = resolve_offline_map_directory(config)
    map_directory = _resolve_path(map_directory, base=config_directory)

    preferences, preference_counts = _read_preferences(
        config,
        Path(ui_state_path),
        Path(database_path),
    )
    emergency_templates, template_count = _read_emergency_templates(
        Path(database_path),
        stamp,
    )
    database_schema, schema_count = _read_database_schema(Path(database_path))
    map_inventory, map_counts = _read_map_inventory(config, Path(map_directory))

    data_payloads: dict[str, bytes] = {
        "data/preferences.json": _canonical_json_bytes(preferences),
        "data/emergency-templates.json": _canonical_json_bytes(emergency_templates),
        "maps/inventory.json": _canonical_json_bytes(map_inventory),
        "schema/database-schema.json": _canonical_json_bytes(database_schema),
    }
    file_contract = {
        name: {
            "bytes": len(data),
            "sha256": _sha256_bytes(data),
        }
        for name, data in sorted(data_payloads.items())
    }
    manifest: dict[str, Any] = {
        "format": BACKUP_FORMAT,
        "format_version": BACKUP_FORMAT_VERSION,
        "created_at": stamp,
        "product_version": version,
        "source_role": source_role,
        "backup_profile": BACKUP_PROFILE,
        "included_domains": [
            "preferences",
            "emergency_templates",
            "map_inventory",
            "database_schema",
        ],
        "excluded_domains": list(EXCLUDED_DOMAINS),
        "privacy_choices": {
            "message_history": False,
            "contacts": False,
            "positions": False,
            "raw_payloads": False,
            "secrets": False,
            "map_files": False,
            "emergency_template_text": True,
        },
        "database_schema_identity": database_schema["identity_sha256"],
        "map_inventory_only": True,
        "map_inventory_truncated": bool(map_inventory["truncated"]),
        "counts": {
            **preference_counts,
            "emergency_templates": template_count,
            "database_schema_objects": schema_count,
            **map_counts,
        },
        "files": file_contract,
    }
    payloads = {"manifest.json": _canonical_json_bytes(manifest), **data_payloads}
    payloads["PACKAGE_CONTENTS.SHA256"] = _package_contents(payloads)
    archive_bytes = _build_archive_bytes(payloads)

    output_path = Path(output_path).expanduser()
    if output_path.suffix.casefold() != ".zip":
        raise BackupError("output path must end with .zip")
    archive_sha256 = _sha256_bytes(archive_bytes)
    sidecar_path = output_path.with_name(output_path.name + ".SHA256")
    sidecar = f"{archive_sha256}  {output_path.name}\n".encode("ascii")
    _write_atomic_pair(output_path, archive_bytes, sidecar_path, sidecar)
    return BackupResult(output_path, sidecar_path, archive_sha256, manifest)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a privacy-minimized GuToChat product backup (backup-only MVP)."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("~/.config/lorachat-v2/config.json").expanduser(),
        help="Path to config.json",
    )
    parser.add_argument("--output", type=Path, required=True, help="Destination .zip")
    parser.add_argument("--database", type=Path, help="Override database path")
    parser.add_argument("--ui-state", type=Path, help="Override ui-state.json path")
    parser.add_argument("--maps", type=Path, help="Override map directory")
    parser.add_argument("--product-version", help="Override product version")
    parser.add_argument(
        "--created-at",
        help="Fixed timezone-aware ISO-8601 timestamp (primarily for tests)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = create_product_backup(
            args.config,
            args.output,
            database_path=args.database,
            ui_state_path=args.ui_state,
            map_directory=args.maps,
            product_version=args.product_version,
            created_at=args.created_at,
        )
    except (BackupError, ValueError, OSError, sqlite3.Error) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 2
    print(f"PRODUCT_BACKUP={result.archive_path}")
    print(f"PRODUCT_BACKUP_SHA256={result.archive_sha256}")
    print(f"PRODUCT_BACKUP_SIDECAR={result.sidecar_path}")
    print("RESTORE_PERFORMED=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
