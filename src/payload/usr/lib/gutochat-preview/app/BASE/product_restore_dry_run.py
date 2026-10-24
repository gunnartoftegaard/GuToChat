#!/usr/bin/env python3
"""Write-free validation for a future GuToChat product restore.

The module validates one product-backup archive and an existing target using
metadata and read-only access only. It never extracts members to disk, changes
configuration, writes SQLite data, creates probe files, or performs restore.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

import product_backup
from emergency_templates import TEMPLATE_FORMAT, TEMPLATE_FORMAT_VERSION
from roles import CANONICAL_ROLES, infer_role_from_config


DRY_RUN_FORMAT = "gutochat-restore-dry-run"
DRY_RUN_FORMAT_VERSION = 1
SUPPORTED_BACKUP_FORMAT = product_backup.BACKUP_FORMAT
SUPPORTED_BACKUP_FORMAT_VERSION = product_backup.BACKUP_FORMAT_VERSION
SUPPORTED_BACKUP_PROFILE = product_backup.BACKUP_PROFILE
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 32 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_SIDECAR_BYTES = 4096
MIN_CONFIG_FREE_BYTES = 64 * 1024
MIN_DATABASE_FREE_BYTES = 1024 * 1024
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
DATA_MEMBERS = (
    "data/emergency-templates.json",
    "data/preferences.json",
    "maps/inventory.json",
    "schema/database-schema.json",
)
EXPECTED_MEMBERS = frozenset(
    {
        "manifest.json",
        "PACKAGE_CONTENTS.SHA256",
        *DATA_MEMBERS,
    }
)
EXPECTED_INCLUDED_DOMAINS = (
    "preferences",
    "emergency_templates",
    "map_inventory",
    "database_schema",
)


class RestoreDryRunError(ValueError):
    """Raised when the backup or target is unsafe or incompatible."""


@dataclass(frozen=True)
class RestoreDryRunResult:
    status: str
    backup_sha256: str
    source_role: str
    target_role: str
    source_product_version: str
    target_product_version: str
    database_schema_identity: str
    archive_bytes: int
    payload_bytes: int
    required_free_bytes: int
    minimum_available_free_bytes: int
    checks: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": DRY_RUN_FORMAT,
            "format_version": DRY_RUN_FORMAT_VERSION,
            "status": self.status,
            "restore_performed": False,
            "backup_sha256": self.backup_sha256,
            "source_role": self.source_role,
            "target_role": self.target_role,
            "source_product_version": self.source_product_version,
            "target_product_version": self.target_product_version,
            "database_schema_identity": self.database_schema_identity,
            "archive_bytes": self.archive_bytes,
            "payload_bytes": self.payload_bytes,
            "required_free_bytes": self.required_free_bytes,
            "minimum_available_free_bytes": self.minimum_available_free_bytes,
            "checks": list(self.checks),
        }


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _strict_json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            parse_constant=_reject_nonstandard_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise RestoreDryRunError(f"invalid strict JSON: {label}") from exc
    if not isinstance(value, dict):
        raise RestoreDryRunError(f"JSON member must contain an object: {label}")
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
        raise RestoreDryRunError("backup data is not strict JSON") from exc
    return (text + "\n").encode("utf-8")


def _regular_file(path: Path, label: str, *, max_bytes: int | None = None) -> os.stat_result:
    try:
        result = path.lstat()
    except FileNotFoundError as exc:
        raise RestoreDryRunError(f"missing {label}") from exc
    except OSError as exc:
        raise RestoreDryRunError(f"cannot inspect {label}") from exc
    if not stat.S_ISREG(result.st_mode) or path.is_symlink():
        raise RestoreDryRunError(f"{label} must be a regular non-symlink file")
    if max_bytes is not None and result.st_size > max_bytes:
        raise RestoreDryRunError(f"{label} exceeds size limit")
    if not result.st_mode & (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH):
        raise RestoreDryRunError(f"{label} has no readable mode bit")
    return result


def _validate_sidecar(archive_path: Path, sidecar_path: Path) -> tuple[str, int]:
    archive_stat = _regular_file(
        archive_path,
        "backup archive",
        max_bytes=MAX_ARCHIVE_BYTES,
    )
    _regular_file(sidecar_path, "SHA256 sidecar", max_bytes=MAX_SIDECAR_BYTES)
    try:
        sidecar_text = sidecar_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise RestoreDryRunError("SHA256 sidecar is not readable ASCII") from exc
    expected_hash = sidecar_text[:64]
    if not HEX_SHA256.fullmatch(expected_hash):
        raise RestoreDryRunError("SHA256 sidecar has invalid digest")
    expected_text = f"{expected_hash}  {archive_path.name}\n"
    if sidecar_text != expected_text:
        raise RestoreDryRunError("SHA256 sidecar has invalid filename or line format")
    actual_hash = _sha256_file(archive_path)
    if actual_hash != expected_hash:
        raise RestoreDryRunError("backup archive SHA256 does not match sidecar")
    return actual_hash, int(archive_stat.st_size)


def _safe_member_name(name: str) -> bool:
    if not name or "\\" in name or "\x00" in name:
        return False
    pure = PurePosixPath(name)
    return not pure.is_absolute() and all(part not in {"", ".", ".."} for part in pure.parts)


def _read_backup_members(archive_path: Path) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise RestoreDryRunError("backup archive contains duplicate member names")
            if set(names) != EXPECTED_MEMBERS:
                raise RestoreDryRunError("backup archive inventory does not match format v1")
            total = 0
            for info in infos:
                if not _safe_member_name(info.filename) or info.is_dir():
                    raise RestoreDryRunError("backup archive contains an unsafe member name")
                if info.flag_bits & 0x1:
                    raise RestoreDryRunError("encrypted ZIP members are not supported")
                if info.compress_type != zipfile.ZIP_DEFLATED:
                    raise RestoreDryRunError("backup member uses unsupported compression")
                if info.date_time != product_backup.ZIP_TIMESTAMP:
                    raise RestoreDryRunError("backup member timestamp violates format contract")
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                file_type = unix_mode & 0o170000
                if file_type not in {0, stat.S_IFREG}:
                    raise RestoreDryRunError("backup archive contains a non-regular member")
                if unix_mode & 0o777 != 0o600:
                    raise RestoreDryRunError("backup member permissions violate format contract")
                if info.file_size > MAX_MEMBER_BYTES:
                    raise RestoreDryRunError("backup member exceeds uncompressed size limit")
                total += int(info.file_size)
                if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
                    raise RestoreDryRunError("backup exceeds total uncompressed size limit")
                if info.file_size and (
                    info.compress_size <= 0
                    or info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
                ):
                    raise RestoreDryRunError("backup member exceeds compression-ratio limit")
            bad_member = archive.testzip()
            if bad_member is not None:
                raise RestoreDryRunError("backup ZIP CRC validation failed")
            return {name: archive.read(name) for name in names}
    except RestoreDryRunError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise RestoreDryRunError("backup archive is not a readable ZIP") from exc


def _parse_internal_manifest(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeError as exc:
        raise RestoreDryRunError("internal SHA256 manifest is not ASCII") from exc
    result: dict[str, str] = {}
    for line in text.splitlines():
        if len(line) < 67 or line[64:66] != "  ":
            raise RestoreDryRunError("internal SHA256 manifest has invalid line format")
        digest, name = line[:64], line[66:]
        if not HEX_SHA256.fullmatch(digest) or not _safe_member_name(name):
            raise RestoreDryRunError("internal SHA256 manifest has invalid entry")
        if name in result:
            raise RestoreDryRunError("internal SHA256 manifest contains duplicates")
        result[name] = digest
    expected = EXPECTED_MEMBERS - {"PACKAGE_CONTENTS.SHA256"}
    if set(result) != expected:
        raise RestoreDryRunError("internal SHA256 manifest inventory is incomplete")
    return result


def _validate_member_contracts(members: Mapping[str, bytes]) -> tuple[dict[str, Any], int]:
    internal = _parse_internal_manifest(members["PACKAGE_CONTENTS.SHA256"])
    for name, expected in internal.items():
        if _sha256_bytes(members[name]) != expected:
            raise RestoreDryRunError(f"internal SHA256 mismatch: {name}")

    manifest = _strict_json_object(members["manifest.json"], "manifest.json")
    if manifest.get("format") != SUPPORTED_BACKUP_FORMAT:
        raise RestoreDryRunError("unsupported backup format")
    if manifest.get("format_version") != SUPPORTED_BACKUP_FORMAT_VERSION:
        raise RestoreDryRunError("unsupported backup format version")
    if manifest.get("backup_profile") != SUPPORTED_BACKUP_PROFILE:
        raise RestoreDryRunError("unsupported backup profile")
    if manifest.get("included_domains") != list(EXPECTED_INCLUDED_DOMAINS):
        raise RestoreDryRunError("backup domain inventory is incompatible")
    if manifest.get("map_inventory_only") is not True:
        raise RestoreDryRunError("backup unexpectedly includes map data")

    source_role = manifest.get("source_role")
    if source_role not in CANONICAL_ROLES:
        raise RestoreDryRunError("backup source role is not canonical")
    product_version = manifest.get("product_version")
    if not isinstance(product_version, str) or not product_version.strip() or len(product_version) > 128:
        raise RestoreDryRunError("backup product version is invalid")
    schema_identity = manifest.get("database_schema_identity")
    if not isinstance(schema_identity, str) or not HEX_SHA256.fullmatch(schema_identity):
        raise RestoreDryRunError("backup schema identity is invalid")

    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != set(DATA_MEMBERS):
        raise RestoreDryRunError("manifest file contract is incomplete")
    payload_bytes = 0
    for name in DATA_MEMBERS:
        contract = files.get(name)
        if not isinstance(contract, dict):
            raise RestoreDryRunError(f"invalid file contract: {name}")
        size = contract.get("bytes")
        digest = contract.get("sha256")
        if not isinstance(size, int) or size < 0 or size != len(members[name]):
            raise RestoreDryRunError(f"file size contract mismatch: {name}")
        if not isinstance(digest, str) or not HEX_SHA256.fullmatch(digest):
            raise RestoreDryRunError(f"invalid file digest contract: {name}")
        if _sha256_bytes(members[name]) != digest:
            raise RestoreDryRunError(f"file digest contract mismatch: {name}")
        payload_bytes += size

    privacy = manifest.get("privacy_choices")
    if not isinstance(privacy, dict):
        raise RestoreDryRunError("privacy contract is missing")
    for key in ("message_history", "contacts", "positions", "raw_payloads", "secrets", "map_files"):
        if privacy.get(key) is not False:
            raise RestoreDryRunError(f"unsupported privacy choice: {key}")

    preferences = _strict_json_object(members["data/preferences.json"], "data/preferences.json")
    if preferences.get("format") != product_backup.PREFERENCES_FORMAT or preferences.get("version") != product_backup.PREFERENCES_FORMAT_VERSION:
        raise RestoreDryRunError("preferences format is incompatible")

    templates = _strict_json_object(
        members["data/emergency-templates.json"],
        "data/emergency-templates.json",
    )
    if templates.get("format") != TEMPLATE_FORMAT or templates.get("version") != TEMPLATE_FORMAT_VERSION:
        raise RestoreDryRunError("emergency-template format is incompatible")
    if not isinstance(templates.get("templates"), list):
        raise RestoreDryRunError("emergency-template payload is invalid")

    maps = _strict_json_object(members["maps/inventory.json"], "maps/inventory.json")
    if maps.get("format") != product_backup.MAP_INVENTORY_FORMAT or maps.get("version") != product_backup.MAP_INVENTORY_FORMAT_VERSION:
        raise RestoreDryRunError("map-inventory format is incompatible")
    if maps.get("map_files_included") is not False or not isinstance(maps.get("entries"), list):
        raise RestoreDryRunError("map-inventory safety contract is invalid")

    schema = _strict_json_object(
        members["schema/database-schema.json"],
        "schema/database-schema.json",
    )
    if schema.get("format") != product_backup.SCHEMA_FORMAT or schema.get("version") != product_backup.SCHEMA_FORMAT_VERSION:
        raise RestoreDryRunError("database-schema format is incompatible")
    if schema.get("raw_sql_included") is not False or not isinstance(schema.get("objects"), list):
        raise RestoreDryRunError("database-schema safety contract is invalid")
    recomputed_identity = _sha256_bytes(_canonical_json_bytes(schema["objects"]))
    if schema.get("identity_sha256") != recomputed_identity:
        raise RestoreDryRunError("embedded database-schema identity is invalid")
    if recomputed_identity != schema_identity:
        raise RestoreDryRunError("manifest and embedded schema identities differ")
    return manifest, payload_bytes


def _read_target_config(path: Path) -> tuple[dict[str, Any], os.stat_result]:
    result = _regular_file(path, "target config", max_bytes=product_backup.MAX_JSON_SOURCE_BYTES)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RestoreDryRunError("target config cannot be read") from exc
    return _strict_json_object(data, "target config"), result


def _resolve_target_database(
    config_path: Path,
    config: Mapping[str, Any],
    override: Path | None,
) -> Path:
    raw = override if override is not None else product_backup.resolve_database_path(config)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = config_path.parent / path
    return path


def _require_restore_target(path: Path, label: str) -> os.stat_result:
    result = _regular_file(path, label)
    if not result.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
        raise RestoreDryRunError(f"{label} has no writable mode bit")
    parent = path.parent
    try:
        parent_result = parent.lstat()
    except OSError as exc:
        raise RestoreDryRunError(f"cannot inspect parent directory for {label}") from exc
    if not stat.S_ISDIR(parent_result.st_mode) or parent.is_symlink():
        raise RestoreDryRunError(f"parent directory for {label} is unsafe")
    required = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
    execute = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    if not parent_result.st_mode & required or not parent_result.st_mode & execute:
        raise RestoreDryRunError(f"parent directory for {label} lacks write/execute mode")
    return result


def _disk_free_bytes(path: Path) -> int:
    return int(shutil.disk_usage(path).free)


def _validate_storage(
    config_path: Path,
    config_stat: os.stat_result,
    database_path: Path,
    database_stat: os.stat_result,
    members: Mapping[str, bytes],
) -> tuple[int, int]:
    config_required = max(
        MIN_CONFIG_FREE_BYTES,
        int(config_stat.st_size)
        + len(members["data/preferences.json"])
        + MIN_CONFIG_FREE_BYTES,
    )
    database_required = max(
        MIN_DATABASE_FREE_BYTES,
        int(database_stat.st_size) * 2
        + len(members["data/emergency-templates.json"]) * 2
        + MIN_CONFIG_FREE_BYTES,
    )
    requirements: dict[int, tuple[Path, int]] = {}
    for parent, device, required in (
        (config_path.parent, config_stat.st_dev, config_required),
        (database_path.parent, database_stat.st_dev, database_required),
    ):
        if device in requirements:
            previous_path, previous_required = requirements[device]
            requirements[device] = (previous_path, previous_required + required)
        else:
            requirements[device] = (parent, required)

    free_values: list[int] = []
    total_required = 0
    for parent, required in requirements.values():
        free = _disk_free_bytes(parent)
        if free < required:
            raise RestoreDryRunError("insufficient free space for conservative restore plan")
        total_required += required
        free_values.append(free)
    return total_required, min(free_values)


def validate_restore_dry_run(
    archive_path: Path,
    target_config_path: Path,
    *,
    sidecar_path: Path | None = None,
    target_database_path: Path | None = None,
    target_product_version: str | None = None,
) -> RestoreDryRunResult:
    """Validate a future restore without writing or extracting any data."""
    archive_path = Path(archive_path).expanduser()
    target_config_path = Path(target_config_path).expanduser()
    sidecar_path = (
        Path(sidecar_path).expanduser()
        if sidecar_path is not None
        else archive_path.with_name(archive_path.name + ".SHA256")
    )
    backup_sha256, archive_bytes = _validate_sidecar(archive_path, sidecar_path)
    members = _read_backup_members(archive_path)
    manifest, payload_bytes = _validate_member_contracts(members)

    config, config_stat = _read_target_config(target_config_path)
    try:
        target_role = infer_role_from_config(dict(config))
    except ValueError as exc:
        raise RestoreDryRunError("target role is invalid") from exc
    source_role = str(manifest["source_role"])
    if target_role != source_role:
        raise RestoreDryRunError("backup role is incompatible with target role")

    target_version = str(
        target_product_version
        if target_product_version is not None
        else config.get("app_version") or ""
    ).strip()
    if not target_version or len(target_version) > 128 or "\n" in target_version or "\r" in target_version:
        raise RestoreDryRunError("target product version is invalid")
    source_version = str(manifest["product_version"])
    if target_version != source_version:
        raise RestoreDryRunError("backup product version is incompatible with target")

    database_path = _resolve_target_database(
        target_config_path,
        config,
        Path(target_database_path) if target_database_path is not None else None,
    )
    if archive_path.resolve() in {target_config_path.resolve(), database_path.resolve()}:
        raise RestoreDryRunError("backup archive overlaps a restore target")
    config_target_stat = _require_restore_target(target_config_path, "target config")
    database_stat = _require_restore_target(database_path, "target database")
    try:
        target_schema, _ = product_backup._read_database_schema(database_path)
    except (product_backup.BackupError, sqlite3.Error, OSError) as exc:
        raise RestoreDryRunError("target database schema cannot be read safely") from exc
    schema_identity = str(manifest["database_schema_identity"])
    if target_schema.get("identity_sha256") != schema_identity:
        raise RestoreDryRunError("backup database schema is incompatible with target")

    required_free, minimum_free = _validate_storage(
        target_config_path,
        config_target_stat,
        database_path,
        database_stat,
        members,
    )
    checks = (
        "external_sha256",
        "zip_structure_crc_and_limits",
        "internal_sha256_contract",
        "backup_format_and_privacy_contract",
        "source_target_role_match",
        "source_target_product_version_match",
        "source_target_database_schema_match",
        "target_path_types_and_mode_bits",
        "conservative_free_space",
        "write_free_execution",
    )
    return RestoreDryRunResult(
        status="PASS",
        backup_sha256=backup_sha256,
        source_role=source_role,
        target_role=target_role,
        source_product_version=source_version,
        target_product_version=target_version,
        database_schema_identity=schema_identity,
        archive_bytes=archive_bytes,
        payload_bytes=payload_bytes,
        required_free_bytes=required_free,
        minimum_available_free_bytes=minimum_free,
        checks=checks,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a GuToChat restore plan without performing restore."
    )
    parser.add_argument("--backup", type=Path, required=True, help="Product-backup ZIP")
    parser.add_argument("--sidecar", type=Path, help="Override .SHA256 sidecar")
    parser.add_argument(
        "--target-config",
        type=Path,
        required=True,
        help="Existing target config.json to inspect read-only",
    )
    parser.add_argument(
        "--target-database",
        type=Path,
        help="Override existing target SQLite database",
    )
    parser.add_argument(
        "--target-product-version",
        help="Override product version derived from target config",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = validate_restore_dry_run(
            args.backup,
            args.target_config,
            sidecar_path=args.sidecar,
            target_database_path=args.target_database,
            target_product_version=args.target_product_version,
        )
    except (RestoreDryRunError, OSError, sqlite3.Error, ValueError) as exc:
        print("RESTORE_DRY_RUN=FAIL")
        print(f"ERROR={exc}")
        print("RESTORE_PERFORMED=false")
        return 2
    print(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
