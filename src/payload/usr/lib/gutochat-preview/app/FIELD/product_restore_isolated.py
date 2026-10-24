#!/usr/bin/env python3
"""Isolated restore for a temporary synthetic GuToChat installation.

This module is intentionally gated by a synthetic-target marker. It restores
only the domains present in the privacy-minimized product-backup format:
portable preferences and emergency templates. Map inventory and database
schema are validation metadata only. The implementation creates a complete
pre-restore snapshot, prepares all replacements off to the side, commits them
as one rollback-capable set, and performs a full post-check before accepting
success.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sqlite3
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

import product_backup
import product_restore_dry_run
from emergency_templates import EmergencyTemplateStore


RESTORE_FORMAT = "gutochat-isolated-restore"
RESTORE_FORMAT_VERSION = 1
SYNTHETIC_TARGET_FORMAT = "gutochat-synthetic-restore-target"
SYNTHETIC_TARGET_VERSION = 1
SNAPSHOT_FORMAT = "gutochat-pre-restore-snapshot"
SNAPSHOT_FORMAT_VERSION = 1
MARKER_NAME = ".gutochat-synthetic-target.json"
SAFE_UI_KEYS = frozenset({"message_view", "favorite_recipients_only"})
SAFE_POSITION_KEYS = frozenset({"storage_enabled", "stale_minutes"})
MAX_TARGET_JSON_BYTES = product_backup.MAX_JSON_SOURCE_BYTES
MAX_FINGERPRINT_ROWS = 100_000
MAX_FINGERPRINT_BYTES = 32 * 1024 * 1024


class IsolatedRestoreError(ValueError):
    """Raised when an isolated restore cannot be completed safely."""


@dataclass(frozen=True)
class IsolatedRestoreResult:
    status: str
    backup_sha256: str
    snapshot_path: Path
    snapshot_sha256: str
    target_root: Path
    target_config_path: Path
    target_database_path: Path
    restored_runtime_preferences: int
    restored_ui_preferences: int
    restored_position_preferences: int
    restored_emergency_templates: int
    checks: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": RESTORE_FORMAT,
            "format_version": RESTORE_FORMAT_VERSION,
            "status": self.status,
            "backup_sha256": self.backup_sha256,
            "snapshot_path": str(self.snapshot_path),
            "snapshot_sha256": self.snapshot_sha256,
            "target_root": str(self.target_root),
            "target_config_path": str(self.target_config_path),
            "target_database_path": str(self.target_database_path),
            "restored": {
                "runtime_preferences": self.restored_runtime_preferences,
                "ui_preferences": self.restored_ui_preferences,
                "position_preferences": self.restored_position_preferences,
                "emergency_templates": self.restored_emergency_templates,
            },
            "checks": list(self.checks),
            "restore_performed": True,
            "operative_restore": False,
            "synthetic_target_only": True,
        }


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _strict_json_object(data: bytes, label: str) -> dict[str, Any]:
    def reject(value: str) -> None:
        raise ValueError(f"non-standard JSON constant: {value}")

    try:
        value = json.loads(data.decode("utf-8"), parse_constant=reject)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise IsolatedRestoreError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise IsolatedRestoreError(f"{label} must contain a JSON object")
    return value


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
        raise IsolatedRestoreError("restore data is not strict JSON") from exc
    return (text + "\n").encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _regular_non_symlink(path: Path, label: str, *, required: bool = True) -> os.stat_result | None:
    try:
        result = path.lstat()
    except FileNotFoundError:
        if required:
            raise IsolatedRestoreError(f"{label} is missing")
        return None
    except OSError as exc:
        raise IsolatedRestoreError(f"{label} cannot be inspected") from exc
    if path.is_symlink() or not stat.S_ISREG(result.st_mode):
        raise IsolatedRestoreError(f"{label} must be a regular non-symlink file")
    return result


def _read_small_json(path: Path, label: str, *, required: bool = True) -> dict[str, Any]:
    result = _regular_non_symlink(path, label, required=required)
    if result is None:
        return {}
    if result.st_size > MAX_TARGET_JSON_BYTES:
        raise IsolatedRestoreError(f"{label} exceeds size limit")
    try:
        return _strict_json_object(path.read_bytes(), label)
    except OSError as exc:
        raise IsolatedRestoreError(f"{label} cannot be read") from exc


def _validate_synthetic_target(target_root: Path, target_config_path: Path) -> dict[str, Any]:
    try:
        root_stat = target_root.lstat()
    except OSError as exc:
        raise IsolatedRestoreError("synthetic target root cannot be inspected") from exc
    if target_root.is_symlink() or not stat.S_ISDIR(root_stat.st_mode):
        raise IsolatedRestoreError("synthetic target root must be a real directory")
    root_resolved = target_root.resolve()
    config_resolved = target_config_path.resolve()
    if not _is_relative_to(config_resolved, root_resolved):
        raise IsolatedRestoreError("target config must be inside synthetic target root")
    marker = _read_small_json(target_root / MARKER_NAME, "synthetic target marker")
    if marker.get("format") != SYNTHETIC_TARGET_FORMAT:
        raise IsolatedRestoreError("synthetic target marker format is invalid")
    if marker.get("version") != SYNTHETIC_TARGET_VERSION:
        raise IsolatedRestoreError("synthetic target marker version is invalid")
    if marker.get("purpose") != "isolated-test-only":
        raise IsolatedRestoreError("synthetic target marker purpose is invalid")
    return marker


def _resolve_target_database(target_config_path: Path, config: Mapping[str, Any]) -> Path:
    raw = product_backup.resolve_database_path(config)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = target_config_path.parent / path
    return path



def _resolve_ui_state(target_config_path: Path, config: Mapping[str, Any]) -> Path:
    raw = config.get("ui_state_file")
    if raw:
        path = Path(str(raw)).expanduser()
        if not path.is_absolute():
            path = target_config_path.parent / path
        return path
    return target_config_path.parent / "ui-state.json"


def _require_quiescent_database(path: Path, target_root: Path) -> None:
    path_resolved = path.resolve()
    if not _is_relative_to(path_resolved, target_root.resolve()):
        raise IsolatedRestoreError("target database must be inside synthetic target root")
    _regular_non_symlink(path, "target database")
    for suffix in ("-wal", "-shm", "-journal"):
        if Path(str(path) + suffix).exists():
            raise IsolatedRestoreError("target database is not quiescent")


def _read_backup_payloads(archive_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        members = product_restore_dry_run._read_backup_members(archive_path)
        manifest, _ = product_restore_dry_run._validate_member_contracts(members)
    except product_restore_dry_run.RestoreDryRunError as exc:
        raise IsolatedRestoreError(str(exc)) from exc
    preferences = _strict_json_object(members["data/preferences.json"], "preferences payload")
    templates = _strict_json_object(
        members["data/emergency-templates.json"],
        "emergency-template payload",
    )
    return manifest, preferences, templates


def _validate_preferences(payload: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    runtime = payload.get("runtime")
    ui = payload.get("ui")
    position = payload.get("position_privacy")
    if not isinstance(runtime, dict) or not isinstance(ui, dict) or not isinstance(position, dict):
        raise IsolatedRestoreError("preferences payload has invalid domains")
    if not set(runtime).issubset(product_backup.SAFE_CONFIG_KEYS):
        raise IsolatedRestoreError("preferences payload contains unsafe runtime keys")
    if not set(ui).issubset(SAFE_UI_KEYS):
        raise IsolatedRestoreError("preferences payload contains unsafe UI keys")
    if not set(position).issubset(SAFE_POSITION_KEYS):
        raise IsolatedRestoreError("preferences payload contains unsafe position keys")
    for key, value in runtime.items():
        if not product_backup._safe_scalar(value) or value is None:
            raise IsolatedRestoreError(f"runtime preference is invalid: {key}")
        if isinstance(value, str) and len(value) > 128:
            raise IsolatedRestoreError(f"runtime preference is too long: {key}")
    if "message_view" in ui and ui["message_view"] not in {"Tabellvisning", "Samtalevisning"}:
        raise IsolatedRestoreError("message_view preference is invalid")
    if "favorite_recipients_only" in ui and not isinstance(ui["favorite_recipients_only"], bool):
        raise IsolatedRestoreError("favorite_recipients_only preference is invalid")
    normalized_position: dict[str, str] = {}
    if "storage_enabled" in position:
        if not isinstance(position["storage_enabled"], bool):
            raise IsolatedRestoreError("storage_enabled preference is invalid")
        normalized_position["storage_enabled"] = "1" if position["storage_enabled"] else "0"
    if "stale_minutes" in position:
        value = position["stale_minutes"]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 365 * 24 * 60:
            raise IsolatedRestoreError("stale_minutes preference is invalid")
        normalized_position["stale_minutes"] = str(value)
    return dict(runtime), dict(ui), normalized_position


def _validate_templates(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw_templates = payload.get("templates")
    if not isinstance(raw_templates, list):
        raise IsolatedRestoreError("emergency-template payload is invalid")
    if len(raw_templates) > product_backup.MAX_EMERGENCY_TEMPLATES:
        raise IsolatedRestoreError("emergency-template payload exceeds limit")
    validator = object.__new__(EmergencyTemplateStore)
    try:
        normalized = [
            validator._normalize_import_template(raw, index=index, format_version=2)
            for index, raw in enumerate(raw_templates, start=1)
        ]
    except ValueError as exc:
        raise IsolatedRestoreError(f"emergency-template payload is invalid: {exc}") from exc
    ids = [str(item["id"]) for item in normalized]
    if len(ids) != len(set(ids)):
        raise IsolatedRestoreError("emergency-template payload contains duplicate IDs")
    return normalized


def _sqlite_backup(source_path: Path, destination_path: Path) -> None:
    uri = f"file:{source_path.resolve().as_posix()}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=10) as source:
            source.execute("PRAGMA query_only=ON")
            with sqlite3.connect(destination_path, timeout=10) as destination:
                source.backup(destination)
                row = destination.execute("PRAGMA integrity_check").fetchone()
                if row is None or str(row[0]).lower() != "ok":
                    raise IsolatedRestoreError("SQLite backup failed integrity check")
    except sqlite3.Error as exc:
        raise IsolatedRestoreError("target database cannot be snapshotted safely") from exc
    os.chmod(destination_path, 0o600)


def _snapshot_archive_bytes(
    *,
    config_bytes: bytes,
    config_mode: int,
    database_bytes: bytes,
    database_mode: int,
    ui_state_bytes: bytes | None,
    ui_state_mode: int | None,
    created_at: str,
) -> bytes:
    files: dict[str, bytes] = {
        "target/config.json": config_bytes,
        "target/messages.db": database_bytes,
    }
    modes: dict[str, str] = {
        "target/config.json": f"{config_mode:04o}",
        "target/messages.db": f"{database_mode:04o}",
    }
    if ui_state_bytes is not None:
        files["target/ui-state.json"] = ui_state_bytes
        modes["target/ui-state.json"] = f"{int(ui_state_mode or 0o600):04o}"
    manifest = {
        "format": SNAPSHOT_FORMAT,
        "format_version": SNAPSHOT_FORMAT_VERSION,
        "created_at": created_at,
        "purpose": "automatic-local-rollback-before-isolated-restore",
        "synthetic_target_only": True,
        "files": {
            name: {
                "bytes": len(data),
                "sha256": _sha256_bytes(data),
                "mode": modes[name],
            }
            for name, data in sorted(files.items())
        },
    }
    payloads = {"manifest.json": _canonical_json_bytes(manifest), **files}
    payloads["PACKAGE_CONTENTS.SHA256"] = product_backup._package_contents(payloads)
    return product_backup._build_archive_bytes(payloads)


def _verify_snapshot(snapshot_path: Path, expected_sha256: str) -> None:
    sidecar = snapshot_path.with_name(snapshot_path.name + ".SHA256")
    _regular_non_symlink(snapshot_path, "pre-restore snapshot")
    _regular_non_symlink(sidecar, "pre-restore snapshot sidecar")
    try:
        sidecar_text = sidecar.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise IsolatedRestoreError("pre-restore snapshot sidecar cannot be read") from exc
    if sidecar_text != f"{expected_sha256}  {snapshot_path.name}\n":
        raise IsolatedRestoreError("pre-restore snapshot sidecar contract failed")
    if _sha256_file(snapshot_path) != expected_sha256:
        raise IsolatedRestoreError("pre-restore snapshot SHA256 verification failed")
    try:
        with zipfile.ZipFile(snapshot_path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise IsolatedRestoreError("pre-restore snapshot contains duplicate members")
            if "manifest.json" not in names or "PACKAGE_CONTENTS.SHA256" not in names:
                raise IsolatedRestoreError("pre-restore snapshot inventory is incomplete")
            if archive.testzip() is not None:
                raise IsolatedRestoreError("pre-restore snapshot CRC verification failed")
            members = {name: archive.read(name) for name in names}
    except (OSError, zipfile.BadZipFile) as exc:
        raise IsolatedRestoreError("pre-restore snapshot is not a readable ZIP") from exc
    try:
        text = members["PACKAGE_CONTENTS.SHA256"].decode("ascii")
    except UnicodeError as exc:
        raise IsolatedRestoreError("pre-restore snapshot internal manifest is not ASCII") from exc
    internal: dict[str, str] = {}
    for line in text.splitlines():
        if len(line) < 67 or line[64:66] != "  ":
            raise IsolatedRestoreError("pre-restore snapshot internal manifest line is invalid")
        digest, name = line[:64], line[66:]
        if not product_restore_dry_run.HEX_SHA256.fullmatch(digest) or not product_restore_dry_run._safe_member_name(name):
            raise IsolatedRestoreError("pre-restore snapshot internal manifest entry is invalid")
        if name in internal:
            raise IsolatedRestoreError("pre-restore snapshot internal manifest has duplicates")
        internal[name] = digest
    expected_members = set(members) - {"PACKAGE_CONTENTS.SHA256"}
    if set(internal) != expected_members:
        raise IsolatedRestoreError("pre-restore snapshot internal inventory mismatch")
    for name, digest in internal.items():
        if _sha256_bytes(members[name]) != digest:
            raise IsolatedRestoreError(f"pre-restore snapshot internal SHA256 mismatch: {name}")
    manifest = _strict_json_object(members["manifest.json"], "pre-restore snapshot manifest")
    if manifest.get("format") != SNAPSHOT_FORMAT or manifest.get("format_version") != SNAPSHOT_FORMAT_VERSION:
        raise IsolatedRestoreError("pre-restore snapshot format is invalid")


def _create_snapshot(
    snapshot_path: Path,
    target_config_path: Path,
    target_database_path: Path,
    ui_state_path: Path,
    *,
    created_at: str,
) -> str:
    config_stat = _regular_non_symlink(target_config_path, "target config")
    database_stat = _regular_non_symlink(target_database_path, "target database")
    ui_stat = _regular_non_symlink(ui_state_path, "target UI state", required=False)
    try:
        config_bytes = target_config_path.read_bytes()
        ui_bytes = None if ui_stat is None else ui_state_path.read_bytes()
    except OSError as exc:
        raise IsolatedRestoreError("target JSON files cannot be snapshotted") from exc
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_db: Path | None = None
    try:
        handle, name = tempfile.mkstemp(prefix=".gutochat-snapshot-db-", dir=snapshot_path.parent)
        os.close(handle)
        temporary_db = Path(name)
        _sqlite_backup(target_database_path, temporary_db)
        archive_bytes = _snapshot_archive_bytes(
            config_bytes=config_bytes,
            config_mode=stat.S_IMODE(config_stat.st_mode),
            database_bytes=temporary_db.read_bytes(),
            database_mode=stat.S_IMODE(database_stat.st_mode),
            ui_state_bytes=ui_bytes,
            ui_state_mode=None if ui_stat is None else stat.S_IMODE(ui_stat.st_mode),
            created_at=created_at,
        )
        digest = _sha256_bytes(archive_bytes)
        sidecar = snapshot_path.with_name(snapshot_path.name + ".SHA256")
        sidecar_bytes = f"{digest}  {snapshot_path.name}\n".encode("ascii")
        product_backup._write_atomic_pair(snapshot_path, archive_bytes, sidecar, sidecar_bytes)
        _verify_snapshot(snapshot_path, digest)
        return digest
    except (OSError, product_backup.BackupError) as exc:
        raise IsolatedRestoreError("pre-restore snapshot could not be created atomically") from exc
    finally:
        if temporary_db is not None:
            try:
                temporary_db.unlink(missing_ok=True)
            except OSError:
                pass


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"blob_sha256": _sha256_bytes(value), "bytes": len(value)}
    return str(value)


def _database_fingerprints(path: Path, excluded_tables: Iterable[str]) -> dict[str, str]:
    excluded = set(excluded_tables)
    result: dict[str, str] = {}
    total_rows = 0
    total_bytes = 0
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=10) as con:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA query_only=ON")
            tables = [
                str(row[0])
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
                if str(row[0]) not in excluded
            ]
            for table in tables:
                quoted = '"' + table.replace('"', '""') + '"'
                rows = []
                for row in con.execute(f"SELECT * FROM {quoted}"):
                    total_rows += 1
                    if total_rows > MAX_FINGERPRINT_ROWS:
                        raise IsolatedRestoreError("synthetic database exceeds fingerprint row limit")
                    values = [_jsonable(value) for value in tuple(row)]
                    encoded = _canonical_json_bytes(values)
                    total_bytes += len(encoded)
                    if total_bytes > MAX_FINGERPRINT_BYTES:
                        raise IsolatedRestoreError("synthetic database exceeds fingerprint byte limit")
                    rows.append(values)
                rows.sort(key=lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False))
                result[table] = _sha256_bytes(_canonical_json_bytes(rows))
    except sqlite3.Error as exc:
        raise IsolatedRestoreError("synthetic database cannot be fingerprinted") from exc
    return result


def _prepare_config(config: Mapping[str, Any], runtime: Mapping[str, Any]) -> bytes:
    restored = dict(config)
    for key in product_backup.SAFE_CONFIG_KEYS:
        restored.pop(key, None)
    restored.update(runtime)
    return _canonical_json_bytes(restored)


def _prepare_ui_state(existing: Mapping[str, Any], ui: Mapping[str, Any]) -> bytes:
    restored = dict(existing)
    for key in SAFE_UI_KEYS:
        restored.pop(key, None)
    restored.update(ui)
    return _canonical_json_bytes(restored)


def _prepare_database(
    target_database_path: Path,
    staged_database_path: Path,
    position: Mapping[str, str],
    templates: list[Mapping[str, Any]],
) -> None:
    _sqlite_backup(target_database_path, staged_database_path)
    try:
        with sqlite3.connect(staged_database_path, timeout=10) as con:
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("BEGIN IMMEDIATE")
            for key in sorted(SAFE_POSITION_KEYS):
                con.execute("DELETE FROM position_settings WHERE key = ?", (key,))
            con.executemany(
                "INSERT INTO position_settings(key, value) VALUES (?, ?)",
                sorted(position.items()),
            )
            con.execute("DELETE FROM emergency_templates")
            con.executemany(
                """
                INSERT INTO emergency_templates(
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
                        item["severity"],
                        str(item["created_at"]),
                        str(item["updated_at"]),
                    )
                    for item in templates
                ],
            )
            con.commit()
            row = con.execute("PRAGMA integrity_check").fetchone()
            if row is None or str(row[0]).lower() != "ok":
                raise IsolatedRestoreError("staged database failed integrity check")
    except sqlite3.Error as exc:
        raise IsolatedRestoreError("restore payload could not be applied to staged database") from exc
    os.chmod(staged_database_path, 0o600)


def _make_stage(parent: Path, prefix: str, data: bytes | None = None) -> Path:
    handle, name = tempfile.mkstemp(prefix=prefix, dir=parent)
    path = Path(name)
    try:
        if data is not None:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        else:
            os.close(handle)
        os.chmod(path, 0o600)
        return path
    except Exception:
        try:
            os.close(handle)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _unused_previous(path: Path) -> Path:
    for index in range(1, 10_000):
        candidate = path.with_name(f".{path.name}.restore-previous-{index:04d}")
        if not candidate.exists():
            return candidate
    raise IsolatedRestoreError("cannot allocate rollback filename")


def _rollback_commit(records: list[tuple[Path, Path | None, bool]]) -> None:
    errors: list[str] = []
    for target, previous, installed in reversed(records):
        try:
            if installed and target.exists():
                target.unlink()
            if previous is not None and previous.exists():
                os.replace(previous, target)
            _fsync_directory(target.parent)
        except OSError as exc:
            errors.append(f"{target.name}: {exc}")
    if errors:
        raise IsolatedRestoreError("rollback failed: " + "; ".join(errors))


def _commit_staged(staged: list[tuple[Path, Path]]) -> list[tuple[Path, Path | None, bool]]:
    records: list[tuple[Path, Path | None, bool]] = []
    try:
        for target, stage in staged:
            previous: Path | None = None
            if target.exists():
                previous = _unused_previous(target)
                os.replace(target, previous)
            records.append((target, previous, False))
            os.replace(stage, target)
            records[-1] = (target, previous, True)
            _fsync_directory(target.parent)
        return records
    except OSError as exc:
        try:
            _rollback_commit(records)
        except IsolatedRestoreError as rollback_exc:
            raise IsolatedRestoreError(
                f"atomic restore commit failed and rollback failed: {rollback_exc}"
            ) from exc
        raise IsolatedRestoreError("atomic restore commit failed; target was rolled back") from exc


def _cleanup_previous(records: Iterable[tuple[Path, Path | None, bool]]) -> None:
    for target, previous, _installed in records:
        if previous is not None:
            previous.unlink(missing_ok=True)
            _fsync_directory(target.parent)


def _read_restored_templates(database_path: Path) -> list[dict[str, Any]]:
    uri = f"file:{database_path.resolve().as_posix()}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=10) as con:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA query_only=ON")
            rows = con.execute(
                "SELECT id, name, category, text, sort_order, requires_confirmation, "
                "severity, created_at, updated_at FROM emergency_templates "
                "ORDER BY sort_order, name, id"
            ).fetchall()
            return [
                {
                    "id": str(row["id"]),
                    "name": str(row["name"]),
                    "category": str(row["category"]),
                    "text": str(row["text"]),
                    "sort_order": int(row["sort_order"]),
                    "requires_confirmation": bool(row["requires_confirmation"]),
                    "severity": None if row["severity"] is None else str(row["severity"]),
                    "created_at": str(row["created_at"]),
                    "updated_at": str(row["updated_at"]),
                }
                for row in rows
            ]
    except sqlite3.Error as exc:
        raise IsolatedRestoreError("restored templates cannot be verified") from exc


def _read_position_settings(database_path: Path) -> dict[str, str]:
    uri = f"file:{database_path.resolve().as_posix()}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=10) as con:
            con.execute("PRAGMA query_only=ON")
            return {
                str(key): str(value)
                for key, value in con.execute(
                    "SELECT key, value FROM position_settings "
                    "WHERE key IN ('storage_enabled', 'stale_minutes') ORDER BY key"
                )
            }
    except sqlite3.Error as exc:
        raise IsolatedRestoreError("restored position preferences cannot be verified") from exc


def _postcheck(
    archive_path: Path,
    target_config_path: Path,
    target_database_path: Path,
    ui_state_path: Path,
    runtime: Mapping[str, Any],
    ui: Mapping[str, Any],
    position: Mapping[str, str],
    templates: list[Mapping[str, Any]],
    untouched_fingerprints: Mapping[str, str],
    sidecar_path: Path,
) -> None:
    product_restore_dry_run.validate_restore_dry_run(
        archive_path,
        target_config_path,
        sidecar_path=sidecar_path,
        target_database_path=target_database_path,
    )
    config = _read_small_json(target_config_path, "restored target config")
    for key in product_backup.SAFE_CONFIG_KEYS:
        if key in runtime:
            if config.get(key) != runtime[key]:
                raise IsolatedRestoreError(f"post-check failed for runtime preference: {key}")
        elif key in config:
            raise IsolatedRestoreError(f"post-check found stale runtime preference: {key}")
    restored_ui = _read_small_json(ui_state_path, "restored target UI state", required=False)
    for key in SAFE_UI_KEYS:
        if key in ui:
            if restored_ui.get(key) != ui[key]:
                raise IsolatedRestoreError(f"post-check failed for UI preference: {key}")
        elif key in restored_ui:
            raise IsolatedRestoreError(f"post-check found stale UI preference: {key}")
    if _read_position_settings(target_database_path) != dict(position):
        raise IsolatedRestoreError("post-check failed for position preferences")
    expected_templates = sorted(
        [dict(item) for item in templates],
        key=lambda item: (int(item["sort_order"]), str(item["name"]), str(item["id"])),
    )
    if _read_restored_templates(target_database_path) != expected_templates:
        raise IsolatedRestoreError("post-check failed for emergency templates")
    after_fingerprints = _database_fingerprints(
        target_database_path,
        {"emergency_templates", "position_settings"},
    )
    if dict(untouched_fingerprints) != after_fingerprints:
        raise IsolatedRestoreError("post-check found changes outside restored database domains")


def restore_to_synthetic_target(
    archive_path: Path,
    target_root: Path,
    target_config_path: Path,
    snapshot_path: Path,
    *,
    sidecar_path: Path | None = None,
    created_at: str | None = None,
) -> IsolatedRestoreResult:
    """Restore a validated product backup into a marked synthetic target."""
    archive_path = Path(archive_path).expanduser()
    target_root = Path(target_root).expanduser()
    target_config_path = Path(target_config_path).expanduser()
    snapshot_path = Path(snapshot_path).expanduser()
    sidecar_path = (
        Path(sidecar_path).expanduser()
        if sidecar_path is not None
        else archive_path.with_name(archive_path.name + ".SHA256")
    )
    created_at = product_backup._validate_iso_timestamp(created_at or _now_iso())

    _validate_synthetic_target(target_root, target_config_path)
    config = _read_small_json(target_config_path, "target config")
    target_database_path = _resolve_target_database(target_config_path, config)
    _require_quiescent_database(target_database_path, target_root)
    dry_run = product_restore_dry_run.validate_restore_dry_run(
        archive_path,
        target_config_path,
        sidecar_path=sidecar_path,
    )
    ui_state_path = _resolve_ui_state(target_config_path, config)
    if ui_state_path.exists():
        ui_resolved = ui_state_path.resolve()
        if not _is_relative_to(ui_resolved, target_root.resolve()):
            raise IsolatedRestoreError("target UI state must be inside synthetic target root")
        _regular_non_symlink(ui_state_path, "target UI state")

    forbidden = {
        archive_path.resolve(),
        sidecar_path.resolve(),
        target_config_path.resolve(),
        target_database_path.resolve(),
        ui_state_path.resolve(),
    }
    if snapshot_path.resolve() in forbidden or snapshot_path.with_name(snapshot_path.name + ".SHA256").resolve() in forbidden:
        raise IsolatedRestoreError("snapshot path overlaps backup or restore targets")
    if _is_relative_to(snapshot_path.resolve(), target_root.resolve()):
        raise IsolatedRestoreError("snapshot must be outside synthetic target root")

    _manifest, preferences_payload, templates_payload = _read_backup_payloads(archive_path)
    runtime, ui, position = _validate_preferences(preferences_payload)
    templates = _validate_templates(templates_payload)
    untouched_before = _database_fingerprints(
        target_database_path,
        {"emergency_templates", "position_settings"},
    )

    snapshot_sha256 = _create_snapshot(
        snapshot_path,
        target_config_path,
        target_database_path,
        ui_state_path,
        created_at=created_at,
    )

    stages: list[Path] = []
    records: list[tuple[Path, Path | None, bool]] = []
    try:
        config_stage = _make_stage(
            target_config_path.parent,
            ".gutochat-restore-config-",
            _prepare_config(config, runtime),
        )
        stages.append(config_stage)
        existing_ui = _read_small_json(ui_state_path, "target UI state", required=False)
        ui_stage = _make_stage(
            ui_state_path.parent,
            ".gutochat-restore-ui-",
            _prepare_ui_state(existing_ui, ui),
        )
        stages.append(ui_stage)
        database_stage = _make_stage(
            target_database_path.parent,
            ".gutochat-restore-db-",
        )
        stages.append(database_stage)
        database_stage.unlink(missing_ok=True)
        _prepare_database(target_database_path, database_stage, position, templates)

        staged_schema, _ = product_backup._read_database_schema(database_stage)
        if staged_schema.get("identity_sha256") != dry_run.database_schema_identity:
            raise IsolatedRestoreError("staged database schema changed unexpectedly")
        if _database_fingerprints(
            database_stage,
            {"emergency_templates", "position_settings"},
        ) != untouched_before:
            raise IsolatedRestoreError("staged database changed an excluded domain")

        staged = [
            (target_database_path, database_stage),
            (ui_state_path, ui_stage),
            (target_config_path, config_stage),
        ]
        records = _commit_staged(staged)
        stages.clear()
        try:
            _postcheck(
                archive_path,
                target_config_path,
                target_database_path,
                ui_state_path,
                runtime,
                ui,
                position,
                templates,
                untouched_before,
                sidecar_path,
            )
        except Exception as exc:
            _rollback_commit(records)
            records = []
            if isinstance(exc, IsolatedRestoreError):
                raise
            raise IsolatedRestoreError("post-check failed; target was rolled back") from exc
        _cleanup_previous(records)
        records = []
    except IsolatedRestoreError:
        raise
    except (OSError, sqlite3.Error, product_backup.BackupError) as exc:
        if records:
            _rollback_commit(records)
            records = []
        raise IsolatedRestoreError("isolated restore failed; target was rolled back") from exc
    finally:
        for stage in stages:
            try:
                stage.unlink(missing_ok=True)
            except OSError:
                pass
        for path in target_root.rglob(".gutochat-restore-*"):
            try:
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            except OSError:
                pass

    checks = (
        "synthetic_target_marker",
        "restore_dry_run_preflight",
        "automatic_pre_restore_snapshot",
        "snapshot_external_and_internal_sha256",
        "quiescent_sqlite_target",
        "staged_restore_before_commit",
        "atomic_multi_file_commit_with_rollback",
        "database_integrity_and_schema_identity",
        "restored_domain_exact_match",
        "excluded_database_domains_unchanged",
        "full_post_restore_dry_run",
        "temporary_and_previous_file_cleanup",
    )
    return IsolatedRestoreResult(
        status="PASS",
        backup_sha256=dry_run.backup_sha256,
        snapshot_path=snapshot_path,
        snapshot_sha256=snapshot_sha256,
        target_root=target_root,
        target_config_path=target_config_path,
        target_database_path=target_database_path,
        restored_runtime_preferences=len(runtime),
        restored_ui_preferences=len(ui),
        restored_position_preferences=len(position),
        restored_emergency_templates=len(templates),
        checks=checks,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Restore a GuToChat backup into a marked temporary synthetic target."
    )
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--sidecar", type=Path)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--target-config", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--created-at")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = restore_to_synthetic_target(
            args.backup,
            args.target_root,
            args.target_config,
            args.snapshot,
            sidecar_path=args.sidecar,
            created_at=args.created_at,
        )
    except (IsolatedRestoreError, product_restore_dry_run.RestoreDryRunError, OSError, sqlite3.Error, ValueError) as exc:
        print("ISOLATED_RESTORE=FAIL")
        print(f"ERROR={exc}")
        print("RESTORE_PERFORMED=false")
        print("OPERATIVE_RESTORE=false")
        return 2
    print(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
