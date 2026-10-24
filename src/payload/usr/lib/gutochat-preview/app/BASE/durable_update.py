#!/usr/bin/env python3
"""Durable/atomic filesystem primitives for GuToChat updater hardening.

The updater must never write candidate bytes directly into the active program
path.  A complete candidate tree is staged on the same filesystem, every
regular file and directory is fsync'ed, then the staged and live directories
are exchanged atomically with renameat2(RENAME_EXCHANGE).

This module is stdlib-only and contains no service, radio, database, or network
operations.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

AT_FDCWD = -100
RENAME_EXCHANGE = 2


def _fsync_fd(fd: int) -> None:
    while True:
        try:
            os.fsync(fd)
            return
        except InterruptedError:
            continue


def fsync_file(path: Path) -> None:
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        _fsync_fd(fd)
    finally:
        os.close(fd)


def fsync_dir(path: Path) -> None:
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        _fsync_fd(fd)
    finally:
        os.close(fd)


def fsync_tree(root: Path, *, allow_symlinks: bool = False) -> None:
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError(f"DURABLE_TREE_INVALID:{root}")
    directories: list[Path] = []
    for parent, dirs, files in os.walk(root, topdown=True, followlinks=False):
        p = Path(parent)
        directories.append(p)
        for name in dirs:
            child = p / name
            if child.is_symlink():
                if allow_symlinks:
                    continue
                raise RuntimeError(f"DURABLE_TREE_SYMLINK_FORBIDDEN:{child}")
        for name in files:
            child = p / name
            st = child.lstat()
            if stat.S_ISLNK(st.st_mode):
                if allow_symlinks:
                    continue
                raise RuntimeError(f"DURABLE_TREE_SYMLINK_FORBIDDEN:{child}")
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError(f"DURABLE_TREE_SPECIAL_FILE_FORBIDDEN:{child}")
            fsync_file(child)
    for directory in reversed(directories):
        fsync_dir(directory)


def _renameat2_exchange(a: Path, b: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    func = getattr(libc, "renameat2", None)
    if func is None:
        raise RuntimeError("DURABLE_RENAME_EXCHANGE_UNAVAILABLE")
    func.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    func.restype = ctypes.c_int
    rc = func(AT_FDCWD, os.fsencode(a), AT_FDCWD, os.fsencode(b), RENAME_EXCHANGE)
    if rc != 0:
        err = ctypes.get_errno()
        if err in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP, errno.EXDEV}:
            raise RuntimeError(f"DURABLE_RENAME_EXCHANGE_UNSUPPORTED:errno={err}")
        raise OSError(err, os.strerror(err), f"{a} <-> {b}")


def assert_exchange_supported(parent: Path) -> None:
    parent = Path(parent).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".gutochat-exchange-probe-", dir=parent) as tmp:
        root = Path(tmp)
        a = root / "a"
        b = root / "b"
        a.mkdir(); b.mkdir()
        (a / "probe").write_bytes(b"A")
        (b / "probe").write_bytes(b"B")
        fsync_tree(a); fsync_tree(b); fsync_dir(root)
        _renameat2_exchange(a, b)
        fsync_dir(root)
        if (a / "probe").read_bytes() != b"B" or (b / "probe").read_bytes() != b"A":
            raise RuntimeError("DURABLE_RENAME_EXCHANGE_PROBE_MISMATCH")


def exchange_dirs(a: Path, b: Path) -> None:
    a = Path(a).resolve()
    b = Path(b).resolve()
    for path in (a, b):
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError(f"DURABLE_EXCHANGE_NOT_DIRECTORY:{path}")
    if a.stat().st_dev != b.stat().st_dev:
        raise RuntimeError("DURABLE_EXCHANGE_CROSS_FILESYSTEM")
    _renameat2_exchange(a, b)
    # Persist both directory-entry changes.  If parents are identical, one fsync is enough.
    parents = {a.parent, b.parent}
    for parent in parents:
        fsync_dir(parent)


def atomic_write_bytes(dest: Path, data: bytes, mode: int = 0o644) -> None:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{dest.name}.gutochat-new-", dir=dest.parent)
    temp = Path(temp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            _fsync_fd(handle.fileno())
        os.replace(temp, dest)
        fsync_dir(dest.parent)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_copy(src: Path, dest: Path, mode: int | None = None) -> None:
    src = Path(src)
    st = src.lstat()
    if not stat.S_ISREG(st.st_mode) or src.is_symlink():
        raise RuntimeError(f"DURABLE_COPY_SOURCE_INVALID:{src}")
    final_mode = stat.S_IMODE(st.st_mode) if mode is None else mode
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{dest.name}.gutochat-new-", dir=dest.parent)
    temp = Path(temp_name)
    try:
        os.fchmod(fd, final_mode)
        with os.fdopen(fd, "wb", closefd=True) as out, src.open("rb") as inp:
            shutil.copyfileobj(inp, out, length=1024 * 1024)
            out.flush()
            _fsync_fd(out.fileno())
        os.replace(temp, dest)
        fsync_dir(dest.parent)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_symlink(target: str, dest: Path) -> None:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = dest.parent / f".{dest.name}.gutochat-link-{os.getpid()}"
    try:
        temp.unlink(missing_ok=True)
        os.symlink(target, temp)
        os.replace(temp, dest)
        fsync_dir(dest.parent)
    finally:
        temp.unlink(missing_ok=True)


def _mode(value: str) -> int:
    return int(value, 8)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("check-exchange")
    p.add_argument("parent", type=Path)
    p = sub.add_parser("sync-tree")
    p.add_argument("path", type=Path)
    p.add_argument("--allow-symlinks", action="store_true")
    p = sub.add_parser("exchange")
    p.add_argument("a", type=Path); p.add_argument("b", type=Path)
    p = sub.add_parser("atomic-write")
    p.add_argument("dest", type=Path); p.add_argument("--mode", type=_mode, default=0o644)
    p = sub.add_parser("atomic-copy")
    p.add_argument("src", type=Path); p.add_argument("dest", type=Path); p.add_argument("--mode", type=_mode)
    p = sub.add_parser("atomic-symlink")
    p.add_argument("target"); p.add_argument("dest", type=Path)
    args = parser.parse_args(argv)

    if args.cmd == "check-exchange":
        assert_exchange_supported(args.parent)
        print("DURABLE_RENAME_EXCHANGE=PASS")
    elif args.cmd == "sync-tree":
        fsync_tree(args.path, allow_symlinks=args.allow_symlinks); print("DURABLE_TREE_FSYNC=PASS")
    elif args.cmd == "exchange":
        exchange_dirs(args.a, args.b); print("DURABLE_DIR_EXCHANGE=PASS")
    elif args.cmd == "atomic-write":
        atomic_write_bytes(args.dest, sys.stdin.buffer.read(), args.mode); print("DURABLE_ATOMIC_WRITE=PASS")
    elif args.cmd == "atomic-copy":
        atomic_copy(args.src, args.dest, args.mode); print("DURABLE_ATOMIC_COPY=PASS")
    elif args.cmd == "atomic-symlink":
        atomic_symlink(args.target, args.dest); print("DURABLE_ATOMIC_SYMLINK=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
