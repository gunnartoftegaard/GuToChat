#!/usr/bin/env python3
"""Local fail-closed APRS-A2 ingress transport for A1H.

This module implements only the local AF_UNIX integration boundary.
It does not open SQLite, does not parse APRS into canonical GuToChat
domain objects, and contains no radio or network forwarding path.

A positive ACK may only be emitted when the supplied persistence handler
explicitly reports persisted=True.  Database ownership remains outside
this module.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import socket
import stat
import threading
from typing import Any, Callable


A2_EVENT_SCHEMA = "gutchat.aprs.rx.v1"
A2_ACK_SCHEMA = "gutchat.aprs.rx.ack.v1"

A2_NETWORK = "classic_aprs_rf"
A2_DIRECTION = "rx"

MAX_FRAME_BYTES = 16384

DEFAULT_SOCKET_PATH = Path(
    "/run/gutochat-aprs-a2/a2-rx.sock"
)

_RECEIVER_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
)


class A2IpcError(RuntimeError):
    """Base class for local A2 IPC failures."""


class A2IpcConfigurationError(ValueError):
    """Raised when A2 IPC configuration is unsafe."""


class A2IpcProtocolError(ValueError):
    """Raised when an A2 IPC request violates the contract."""


@dataclass(frozen=True)
class A2IpcConfig:
    enabled: bool = False
    socket_path: Path | None = None
    receiver_id: str = ""
    max_frame_bytes: int = MAX_FRAME_BYTES

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise A2IpcConfigurationError(
                "A2 IPC enabled flag must be boolean"
            )

        if not self.enabled:
            if self.socket_path is not None:
                raise A2IpcConfigurationError(
                    "Disabled A2 IPC must not have a socket path"
                )
            if self.receiver_id:
                raise A2IpcConfigurationError(
                    "Disabled A2 IPC must not have a receiver_id"
                )
            return

        if self.socket_path is None:
            raise A2IpcConfigurationError(
                "Enabled A2 IPC requires socket_path"
            )

        path = Path(self.socket_path).expanduser()

        if not path.is_absolute():
            raise A2IpcConfigurationError(
                "A2 IPC socket path must be absolute"
            )

        path = Path(os.path.abspath(path))

        text = str(path)
        if (
            text == "/tmp"
            or text.startswith("/tmp/")
            or text == "/var/tmp"
            or text.startswith("/var/tmp/")
        ):
            raise A2IpcConfigurationError(
                "A2 IPC socket must not use shared temporary storage"
            )

        receiver = str(self.receiver_id).strip()

        if not _RECEIVER_ID_RE.fullmatch(receiver):
            raise A2IpcConfigurationError(
                "Invalid A2 receiver_id"
            )

        if int(self.max_frame_bytes) != MAX_FRAME_BYTES:
            raise A2IpcConfigurationError(
                "A2 IPC frame limit is fixed at 16384 bytes"
            )

        object.__setattr__(
            self,
            "socket_path",
            path,
        )
        object.__setattr__(
            self,
            "receiver_id",
            receiver,
        )


def build_a2_ipc_config(
    config: dict[str, Any],
) -> A2IpcConfig:
    """Build an inert-by-default local A2 IPC configuration."""
    key = "map_aprs_a2_ipc_enabled"

    if key in config and not isinstance(config[key], bool):
        raise A2IpcConfigurationError(
            "map_aprs_a2_ipc_enabled must be boolean"
        )

    enabled = bool(config.get(key, False))

    if not enabled:
        return A2IpcConfig(enabled=False)

    raw_socket = str(
        config.get(
            "map_aprs_a2_ipc_socket",
            "",
        )
    ).strip()

    raw_receiver = str(
        config.get(
            "map_aprs_a2_receiver_id",
            "",
        )
    ).strip()

    if not raw_socket:
        raise A2IpcConfigurationError(
            "Enabled A2 IPC requires map_aprs_a2_ipc_socket"
        )

    if not raw_receiver:
        raise A2IpcConfigurationError(
            "Enabled A2 IPC requires map_aprs_a2_receiver_id"
        )

    return A2IpcConfig(
        enabled=True,
        socket_path=Path(raw_socket),
        receiver_id=raw_receiver,
    )


def _validate_received_at(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise A2IpcProtocolError(
            "received_at must be a non-empty string"
        )

    text = value.strip()

    try:
        parsed = datetime.fromisoformat(
            text.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise A2IpcProtocolError(
            "received_at must be ISO-8601"
        ) from exc

    if parsed.utcoffset() is None:
        raise A2IpcProtocolError(
            "received_at must include a timezone offset"
        )

    return text


def validate_a2_event(
    value: Any,
) -> dict[str, Any]:
    """Validate only the 0.4a/0.4c integration envelope.

    raw_tnc2 is the canonical integration payload.  Any normalized APRS
    fields carried by a producer remain non-authoritative and are ignored
    by this transport layer.
    """
    if not isinstance(value, dict):
        raise A2IpcProtocolError(
            "A2 event must be a JSON object"
        )

    if value.get("schema") != A2_EVENT_SCHEMA:
        raise A2IpcProtocolError(
            "Unsupported A2 event schema"
        )

    if value.get("network") != A2_NETWORK:
        raise A2IpcProtocolError(
            "Invalid A2 event network"
        )

    if value.get("direction") != A2_DIRECTION:
        raise A2IpcProtocolError(
            "Invalid A2 event direction"
        )

    if "receiver_id" in value:
        raise A2IpcProtocolError(
            "receiver_id is server-side only"
        )

    raw = value.get("raw_tnc2")

    if not isinstance(raw, str) or not raw.strip():
        raise A2IpcProtocolError(
            "raw_tnc2 must be non-empty"
        )

    if "\r" in raw or "\n" in raw:
        raise A2IpcProtocolError(
            "raw_tnc2 must contain exactly one logical line"
        )

    received_at = _validate_received_at(
        value.get("received_at")
    )

    result = dict(value)
    result["raw_tnc2"] = raw
    result["received_at"] = received_at
    return result


PersistenceHandler = Callable[
    [dict[str, Any], str],
    dict[str, Any],
]


def _ack(
    *,
    ok: bool,
    code: str,
    persistence: dict[str, Any] | None = None,
) -> bytes:
    payload: dict[str, Any] = {
        "schema": A2_ACK_SCHEMA,
        "ok": bool(ok),
        "code": str(code),
    }

    if persistence is not None:
        for key in (
            "receipt_store_result",
            "domain_store_result",
        ):
            value = persistence.get(key)
            if isinstance(value, str) and value:
                payload[key] = value

    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


class A2UnixIngressServer:
    """Single-active-client local A2 AF_UNIX ingress server."""

    def __init__(
        self,
        config: A2IpcConfig,
        persistence_handler: PersistenceHandler,
    ) -> None:
        if not config.enabled:
            raise A2IpcConfigurationError(
                "Cannot start disabled A2 IPC server"
            )

        if not callable(persistence_handler):
            raise TypeError(
                "persistence_handler must be callable"
            )

        self.config = config
        self.persistence_handler = persistence_handler

        self._stop_event = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None

        self._lock = threading.Lock()
        self._active_client = False
        self._client_sockets: set[socket.socket] = set()
        self._client_threads: set[threading.Thread] = set()

    @property
    def running(self) -> bool:
        thread = self._thread
        return bool(
            thread is not None
            and thread.is_alive()
        )

    @property
    def client_active(self) -> bool:
        with self._lock:
            return self._active_client

    def _prepare_socket_path(self) -> Path:
        path = self.config.socket_path

        if path is None:
            raise A2IpcConfigurationError(
                "Missing A2 IPC socket path"
            )

        parent = path.parent

        if parent.is_symlink():
            raise A2IpcConfigurationError(
                "A2 IPC socket parent must not be a symlink"
            )

        if not parent.is_dir():
            raise A2IpcConfigurationError(
                "A2 IPC socket parent must already exist"
            )

        parent_stat = parent.stat()

        if parent_stat.st_uid != os.getuid():
            raise A2IpcConfigurationError(
                "A2 IPC socket parent must be owned by service user"
            )

        if parent_stat.st_mode & (
            stat.S_IWGRP | stat.S_IWOTH
        ):
            raise A2IpcConfigurationError(
                "A2 IPC socket parent must not be group/world writable"
            )

        try:
            existing = path.lstat()
        except FileNotFoundError:
            return path

        if not stat.S_ISSOCK(existing.st_mode):
            raise A2IpcConfigurationError(
                "Existing A2 IPC path is not a socket"
            )

        if existing.st_uid != os.getuid():
            raise A2IpcConfigurationError(
                "Existing A2 IPC socket has wrong owner"
            )

        path.unlink()
        return path

    def start(self) -> None:
        if self.running:
            raise A2IpcError(
                "A2 IPC server is already running"
            )

        path = self._prepare_socket_path()

        listener = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

        try:
            listener.bind(str(path))
            os.chmod(path, 0o600)
            listener.listen(4)
            listener.settimeout(0.1)
        except BaseException:
            listener.close()
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            raise

        self._stop_event.clear()
        self._listener = listener

        thread = threading.Thread(
            target=self._accept_loop,
            name="gutochat-a2-unix-ingress",
            daemon=True,
        )
        self._thread = thread
        thread.start()

    def _accept_loop(self) -> None:
        listener = self._listener

        if listener is None:
            return

        while not self._stop_event.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                continue

            conn.settimeout(0.1)

            with self._lock:
                if self._active_client:
                    busy = True
                else:
                    busy = False
                    self._active_client = True
                    self._client_sockets.add(conn)

            if busy:
                try:
                    conn.sendall(
                        _ack(
                            ok=False,
                            code="CLIENT_BUSY",
                        )
                    )
                except OSError:
                    pass
                finally:
                    conn.close()
                continue

            worker = threading.Thread(
                target=self._serve_client,
                args=(conn,),
                name="gutochat-a2-unix-client",
                daemon=True,
            )

            with self._lock:
                self._client_threads.add(worker)

            worker.start()

    def _serve_client(
        self,
        conn: socket.socket,
    ) -> None:
        buffer = bytearray()

        try:
            while not self._stop_event.is_set():
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break

                if not chunk:
                    break

                buffer.extend(chunk)

                if (
                    b"\n" not in buffer
                    and len(buffer) > self.config.max_frame_bytes
                ):
                    try:
                        conn.sendall(
                            _ack(
                                ok=False,
                                code="FRAME_TOO_LARGE",
                            )
                        )
                    except OSError:
                        pass
                    return

                while b"\n" in buffer:
                    frame, _, remainder = buffer.partition(
                        b"\n"
                    )
                    buffer = bytearray(remainder)

                    if frame.endswith(b"\r"):
                        frame = frame[:-1]

                    if len(frame) > self.config.max_frame_bytes:
                        conn.sendall(
                            _ack(
                                ok=False,
                                code="FRAME_TOO_LARGE",
                            )
                        )
                        return

                    response = self._process_frame(
                        bytes(frame)
                    )

                    try:
                        conn.sendall(response)
                    except OSError:
                        return

        finally:
            with self._lock:
                self._client_sockets.discard(conn)
                self._active_client = False
                current = threading.current_thread()
                self._client_threads.discard(current)

            try:
                conn.close()
            except OSError:
                pass

    def _process_frame(
        self,
        frame: bytes,
    ) -> bytes:
        if not frame:
            return _ack(
                ok=False,
                code="EMPTY_FRAME",
            )

        try:
            text = frame.decode(
                "utf-8",
                errors="strict",
            )
        except UnicodeDecodeError:
            return _ack(
                ok=False,
                code="INVALID_UTF8",
            )

        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            return _ack(
                ok=False,
                code="INVALID_JSON",
            )

        try:
            event = validate_a2_event(decoded)
        except A2IpcProtocolError:
            return _ack(
                ok=False,
                code="INVALID_EVENT",
            )

        try:
            persistence = self.persistence_handler(
                event,
                self.config.receiver_id,
            )
        except BaseException:
            return _ack(
                ok=False,
                code="PERSISTENCE_ERROR",
            )

        if not isinstance(persistence, dict):
            return _ack(
                ok=False,
                code="PERSISTENCE_NOT_CONFIRMED",
            )

        if persistence.get("persisted") is not True:
            return _ack(
                ok=False,
                code="PERSISTENCE_NOT_CONFIRMED",
            )

        return _ack(
            ok=True,
            code="PERSISTED",
            persistence=persistence,
        )

    def stop(
        self,
        *,
        join_timeout: float = 2.0,
    ) -> bool:
        timeout = float(join_timeout)

        if not 0.1 <= timeout <= 10.0:
            raise ValueError(
                "A2 IPC join timeout must be within 0.1..10 seconds"
            )

        self._stop_event.set()

        listener = self._listener
        self._listener = None

        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass

        with self._lock:
            clients = list(self._client_sockets)

        for conn in clients:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

        thread = self._thread
        self._thread = None

        if thread is not None:
            thread.join(timeout)

        with self._lock:
            workers = list(self._client_threads)

        for worker in workers:
            worker.join(timeout)

        path = self.config.socket_path

        if path is not None:
            try:
                current = path.lstat()

                if (
                    stat.S_ISSOCK(current.st_mode)
                    and current.st_uid == os.getuid()
                ):
                    path.unlink()
            except FileNotFoundError:
                pass

        with self._lock:
            clean = (
                not self._client_threads
                and not self._client_sockets
                and not self._active_client
            )

        if thread is not None and thread.is_alive():
            clean = False

        return clean
