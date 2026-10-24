#!/usr/bin/env python3
"""Fail-closed local MBTiles installer primitive for GuToChat.

This module is intentionally UI-, radio-, network-, database- and service-neutral.
It installs exactly one already-local MBTiles candidate into an existing active
map directory through a separate staging directory on the same filesystem.

Safety properties:
* source and directories must be non-symlink regular file/directories;
* destination is one plain .mbtiles basename (no traversal/subdirectories);
* candidate is copied to staging, SHA256 recorded, chmod 0644, then validated
  with offline_map.read_map_package() (SQLite mode=ro);
* existing destination always fails closed; no overwrite/delete path;
* active inventory bound is checked before promotion;
* promotion uses hard-link creation, which atomically fails if destination
  already exists, followed by staged-file unlink;
* destination is re-hashed, re-validated, and required to appear in the normal
  operator inventory after promotion.

No rollback ever deletes a pre-existing destination. On a failure before atomic
promotion, only the private staged candidate is removed. If post-promotion
verification unexpectedly fails, the newly installed destination is retained
and the caller receives an explicit fail-closed error requiring operator review;
this avoids an implicit DELETE during an install path.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Any

from offline_map import MAX_DISCOVERED_MAP_FILES, read_map_package
from map_package_operator import build_operator_map_inventory

INSTALL_MODE = 0o644
_COPY_CHUNK = 1024 * 1024


class SecureMbtilesInstallError(RuntimeError):
    """Fail-closed installer error."""


@dataclass(frozen=True)
class SecureMbtilesInstallResult:
    source_path: Path
    destination_path: Path
    sha256: str
    package_name: str
    inventory_key: str
    installed_mode: int


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise SecureMbtilesInstallError(f"{label} kan ikke undersøkes: {path}") from exc


def _require_regular_non_symlink(path: Path, label: str) -> os.stat_result:
    st = _lstat(path, label)
    if not stat.S_ISREG(st.st_mode):
        raise SecureMbtilesInstallError(f"{label} er ikke en regulær fil: {path}")
    return st


def _require_directory_non_symlink(path: Path, label: str) -> os.stat_result:
    st = _lstat(path, label)
    if not stat.S_ISDIR(st.st_mode):
        raise SecureMbtilesInstallError(f"{label} er ikke en regulær katalog: {path}")
    return st


def _validate_destination_name(name: str) -> str:
    value = str(name or "").strip()
    if not value:
        raise SecureMbtilesInstallError("destinasjonsnavn mangler")
    if value in {".", ".."}:
        raise SecureMbtilesInstallError("ugyldig destinasjonsnavn")
    if Path(value).name != value or "/" in value or "\\" in value:
        raise SecureMbtilesInstallError("destinasjonsnavn kan ikke inneholde baneelementer")
    if Path(value).suffix.casefold() != ".mbtiles":
        raise SecureMbtilesInstallError("destinasjonsnavn må ende med .mbtiles")
    return value


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(_COPY_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.absolute().relative_to(parent.absolute())
        return True
    except ValueError:
        return False


def _count_regular_mbtiles(root: Path) -> int:
    count = 0
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        directory_names[:] = [
            name for name in directory_names
            if not (current_path / name).is_symlink()
        ]
        for name in file_names:
            p = current_path / name
            if p.suffix.casefold() != ".mbtiles":
                continue
            try:
                mode = p.lstat().st_mode
            except OSError:
                continue
            if stat.S_ISREG(mode):
                count += 1
    return count


def _copy_candidate_nofollow(source: Path, staged: Path) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        src_fd = os.open(source, flags)
    except OSError as exc:
        raise SecureMbtilesInstallError(f"kandidatfilen kan ikke åpnes sikkert: {source}") from exc
    try:
        src_stat = os.fstat(src_fd)
        if not stat.S_ISREG(src_stat.st_mode):
            raise SecureMbtilesInstallError("kandidatfilen er ikke regulær etter sikker åpning")
        try:
            dst_fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, INSTALL_MODE)
        except OSError as exc:
            raise SecureMbtilesInstallError(f"stagingfil kan ikke opprettes: {staged}") from exc
        try:
            digest = hashlib.sha256()
            with os.fdopen(os.dup(src_fd), "rb", closefd=True) as src_f, os.fdopen(dst_fd, "wb", closefd=True) as dst_f:
                while True:
                    chunk = src_f.read(_COPY_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
                    dst_f.write(chunk)
                dst_f.flush()
                os.fsync(dst_f.fileno())
        finally:
            # dst_fd is owned/closed by fdopen on success; close only if still valid.
            try:
                os.close(dst_fd)
            except OSError:
                pass
    finally:
        os.close(src_fd)
    return digest.hexdigest()


def secure_install_mbtiles(
    source_path: Path,
    map_directory: Path,
    staging_directory: Path,
    *,
    config: Mapping[str, Any],
    destination_name: str | None = None,
    expected_sha256: str | None = None,
    promote: Callable[[Path, Path], None] | None = None,
) -> SecureMbtilesInstallResult:
    """Validate, stage and atomically add one MBTiles package without overwrite.

    ``staging_directory`` must already exist, must not be inside ``map_directory``,
    and must reside on the same filesystem. No directories are created here.
    """
    source = Path(source_path)
    map_dir = Path(map_directory)
    staging_dir = Path(staging_directory)

    _require_regular_non_symlink(source, "kandidatfil")
    if source.suffix.casefold() != ".mbtiles":
        raise SecureMbtilesInstallError("kandidatfilen må ende med .mbtiles")
    map_stat = _require_directory_non_symlink(map_dir, "aktiv kartkatalog")
    stage_stat = _require_directory_non_symlink(staging_dir, "stagingkatalog")

    if _is_within(staging_dir, map_dir):
        raise SecureMbtilesInstallError("stagingkatalog kan ikke ligge i aktiv kartkatalog")
    if map_stat.st_dev != stage_stat.st_dev:
        raise SecureMbtilesInstallError("staging og aktiv kartkatalog må ligge på samme filesystem")

    name = _validate_destination_name(destination_name or source.name)
    destination = map_dir / name
    if destination.exists() or destination.is_symlink():
        raise SecureMbtilesInstallError(f"destinasjonen finnes allerede: {destination}")

    if _count_regular_mbtiles(map_dir) >= MAX_DISCOVERED_MAP_FILES:
        raise SecureMbtilesInstallError("aktiv kartkatalog har nådd MBTiles inventory-grensen")

    token = uuid.uuid4().hex
    staged = staging_dir / f".gutochat-stage-{token}-{name}"
    promoted = False
    try:
        source_hash = _copy_candidate_nofollow(source, staged)
        if expected_sha256 is not None and source_hash.casefold() != str(expected_sha256).strip().casefold():
            raise SecureMbtilesInstallError("kandidatens SHA256 matcher ikke forventet verdi")
        os.chmod(staged, INSTALL_MODE, follow_symlinks=False)
        staged_hash = _sha256_file(staged)
        if staged_hash != source_hash:
            raise SecureMbtilesInstallError("SHA256 endret under staging")

        package = read_map_package(staged)

        if destination.exists() or destination.is_symlink():
            raise SecureMbtilesInstallError(f"destinasjonen finnes allerede: {destination}")

        if promote is None:
            def promote(src: Path, dst: Path) -> None:
                os.link(src, dst, follow_symlinks=False)

        try:
            promote(staged, destination)
        except FileExistsError as exc:
            raise SecureMbtilesInstallError(f"destinasjonen ble opprettet før promotion: {destination}") from exc
        except OSError as exc:
            raise SecureMbtilesInstallError("atomisk promotion feilet") from exc
        promoted = True
        staged.unlink()

        dest_stat = _require_regular_non_symlink(destination, "installert kartfil")
        mode = stat.S_IMODE(dest_stat.st_mode)
        if mode != INSTALL_MODE:
            raise SecureMbtilesInstallError(f"installert filmodus er {oct(mode)}, forventet {oct(INSTALL_MODE)}")
        if _sha256_file(destination) != source_hash:
            raise SecureMbtilesInstallError("SHA256 av installert kartfil matcher ikke staged kandidat")

        installed_package = read_map_package(destination)
        entries = build_operator_map_inventory(config)
        matching = [e for e in entries if e.package.path == destination]
        if len(matching) != 1:
            raise SecureMbtilesInstallError("installert kartfil finnes ikke entydig i operator inventory")

        return SecureMbtilesInstallResult(
            source_path=source,
            destination_path=destination,
            sha256=source_hash,
            package_name=installed_package.name,
            inventory_key=matching[0].key,
            installed_mode=mode,
        )
    except Exception:
        # Only remove private staging. Never auto-delete a promoted destination.
        if not promoted:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass
        raise
