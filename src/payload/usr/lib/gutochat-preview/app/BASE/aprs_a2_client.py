#!/usr/bin/env python3
"""APRS-A2 producer-side AF_UNIX transport.

This module has deliberately no SQLite, AprsStore, APRS parser, RF-control,
receipt-store, or systemd ownership.  It validates one canonical A2 event,
keeps exactly one in-memory pending frame, and advances only after the A1H
server returns a positive PERSISTED acknowledgement.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable

from aprs_a2_ipc import (
    A2_ACK_SCHEMA,
    A2IpcProtocolError,
    DEFAULT_SOCKET_PATH,
    MAX_FRAME_BYTES,
    validate_a2_event,
)


RETRYABLE_ACK_CODES = {
    "PERSISTENCE_ERROR",
    "PERSISTENCE_NOT_CONFIRMED",
}

FATAL_ACK_CODES = {
    "EMPTY_FRAME",
    "INVALID_UTF8",
    "INVALID_JSON",
    "INVALID_EVENT",
    "FRAME_TOO_LARGE",
}


class A2ClientError(RuntimeError):
    """Base producer-side transport failure."""


class A2ClientProtocolError(A2ClientError):
    """Fatal producer, event, or acknowledgement contract failure."""


class A2ClientStopped(A2ClientError):
    """Client shutdown interrupted a pending or retrying event."""

    def __init__(self, message: str, *, pending: bool) -> None:
        super().__init__(message)
        self.pending = bool(pending)


@dataclass(frozen=True)
class A2ClientConfig:
    socket_path: Path = DEFAULT_SOCKET_PATH
    connect_timeout_seconds: float = 1.0
    ack_timeout_seconds: float = 5.0
    reconnect_initial_seconds: float = 0.25
    reconnect_max_seconds: float = 2.0
    reconnect_multiplier: float = 2.0
    max_frame_bytes: int = MAX_FRAME_BYTES

    def __post_init__(self) -> None:
        path = Path(self.socket_path)

        if not str(path):
            raise ValueError("socket_path must be non-empty")

        object.__setattr__(self, "socket_path", path)

        if self.connect_timeout_seconds <= 0:
            raise ValueError("connect_timeout_seconds must be positive")

        if self.ack_timeout_seconds <= 0:
            raise ValueError("ack_timeout_seconds must be positive")

        if self.reconnect_initial_seconds <= 0:
            raise ValueError("reconnect_initial_seconds must be positive")

        if self.reconnect_max_seconds <= 0:
            raise ValueError("reconnect_max_seconds must be positive")

        if (
            self.reconnect_initial_seconds
            > self.reconnect_max_seconds
        ):
            raise ValueError(
                "reconnect_initial_seconds exceeds reconnect_max_seconds"
            )

        if self.reconnect_multiplier < 1.0:
            raise ValueError("reconnect_multiplier must be at least 1")

        if self.max_frame_bytes <= 0:
            raise ValueError("max_frame_bytes must be positive")


SocketFactory = Callable[[int, int], socket.socket]


class A2UnixClient:
    """One-in-flight AF_UNIX client with exact in-memory replay."""

    def __init__(
        self,
        config: A2ClientConfig | None = None,
        *,
        socket_factory: SocketFactory = socket.socket,
    ) -> None:
        self.config = config or A2ClientConfig()
        self._socket_factory = socket_factory

        self._stop_event = threading.Event()
        self._socket_lock = threading.Lock()
        self._socket: socket.socket | None = None

    @property
    def stopped(self) -> bool:
        return self._stop_event.is_set()

    def request_stop(self) -> None:
        self._stop_event.set()
        self._drop_connection()

    def close(self) -> None:
        self._drop_connection()

    def _drop_connection(self) -> None:
        with self._socket_lock:
            sock = self._socket
            self._socket = None

        if sock is None:
            return

        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        try:
            sock.close()
        except OSError:
            pass

    def _current_socket(self) -> socket.socket | None:
        with self._socket_lock:
            return self._socket

    def _set_socket(self, sock: socket.socket) -> None:
        with self._socket_lock:
            if self._stop_event.is_set():
                try:
                    sock.close()
                except OSError:
                    pass
                raise A2ClientStopped(
                    "client stopped while connecting",
                    pending=True,
                )

            self._socket = sock

    def _connect_once(self) -> socket.socket:
        sock = self._socket_factory(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

        try:
            sock.settimeout(
                self.config.connect_timeout_seconds
            )
            sock.connect(
                str(self.config.socket_path)
            )
        except BaseException:
            try:
                sock.close()
            except OSError:
                pass
            raise

        self._set_socket(sock)
        return sock

    def _interruptible_wait(
        self,
        seconds: float,
        *,
        pending: bool,
    ) -> None:
        if self._stop_event.wait(seconds):
            raise A2ClientStopped(
                "client stopped during reconnect wait",
                pending=pending,
            )

    def _validated_frame(
        self,
        value: Any,
    ) -> bytes:
        try:
            event = validate_a2_event(value)
        except A2IpcProtocolError as exc:
            raise A2ClientProtocolError(
                "invalid producer event"
            ) from exc

        try:
            body = json.dumps(
                event,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8", "strict")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise A2ClientProtocolError(
                "producer event cannot be canonicalized"
            ) from exc

        if not body:
            raise A2ClientProtocolError(
                "empty canonical event frame"
            )

        if len(body) > self.config.max_frame_bytes:
            raise A2ClientProtocolError(
                "canonical event frame exceeds maximum"
            )

        return body + b"\n"

    def _read_ack(
        self,
        sock: socket.socket,
    ) -> dict[str, Any]:
        deadline = (
            time.monotonic()
            + self.config.ack_timeout_seconds
        )

        buffer = bytearray()

        while True:
            if self._stop_event.is_set():
                raise A2ClientStopped(
                    "client stopped while awaiting acknowledgement",
                    pending=True,
                )

            remaining = deadline - time.monotonic()

            if remaining <= 0:
                raise TimeoutError(
                    "A2 acknowledgement timeout"
                )

            sock.settimeout(
                min(0.10, remaining)
            )

            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue

            if not chunk:
                raise EOFError(
                    "A2 server closed before acknowledgement"
                )

            buffer.extend(chunk)

            if (
                b"\n" not in buffer
                and len(buffer) > self.config.max_frame_bytes
            ):
                raise A2ClientProtocolError(
                    "acknowledgement frame exceeds maximum"
                )

            if b"\n" not in buffer:
                continue

            frame, _, remainder = buffer.partition(b"\n")

            if remainder:
                raise A2ClientProtocolError(
                    "unexpected extra acknowledgement data"
                )

            if frame.endswith(b"\r"):
                frame = frame[:-1]

            if not frame:
                raise A2ClientProtocolError(
                    "empty acknowledgement frame"
                )

            if len(frame) > self.config.max_frame_bytes:
                raise A2ClientProtocolError(
                    "acknowledgement frame exceeds maximum"
                )

            try:
                text = frame.decode(
                    "utf-8",
                    errors="strict",
                )
            except UnicodeDecodeError as exc:
                raise A2ClientProtocolError(
                    "acknowledgement is not UTF-8"
                ) from exc

            try:
                decoded = json.loads(text)
            except json.JSONDecodeError as exc:
                raise A2ClientProtocolError(
                    "acknowledgement is not JSON"
                ) from exc

            if not isinstance(decoded, dict):
                raise A2ClientProtocolError(
                    "acknowledgement is not an object"
                )

            return decoded

    @staticmethod
    def _classify_ack(
        ack: dict[str, Any],
    ) -> str:
        if ack.get("schema") != A2_ACK_SCHEMA:
            raise A2ClientProtocolError(
                "unsupported acknowledgement schema"
            )

        ok = ack.get("ok")
        code = ack.get("code")

        if type(ok) is not bool:
            raise A2ClientProtocolError(
                "acknowledgement ok must be boolean"
            )

        if not isinstance(code, str) or not code:
            raise A2ClientProtocolError(
                "acknowledgement code is invalid"
            )

        if ok is True:
            if code != "PERSISTED":
                raise A2ClientProtocolError(
                    "unknown positive acknowledgement"
                )
            return "persisted"

        if code in RETRYABLE_ACK_CODES:
            return "retry"

        if code in FATAL_ACK_CODES:
            raise A2ClientProtocolError(
                "server rejected event: " + code
            )

        raise A2ClientProtocolError(
            "unknown negative acknowledgement: " + code
        )

    def send_event(
        self,
        value: Any,
    ) -> dict[str, Any]:
        """Persist one event or retain it in memory until retry succeeds."""
        frame = self._validated_frame(value)

        backoff = self.config.reconnect_initial_seconds

        while True:
            if self._stop_event.is_set():
                raise A2ClientStopped(
                    "client stopped with unacknowledged event",
                    pending=True,
                )

            sock = self._current_socket()

            if sock is None:
                try:
                    sock = self._connect_once()
                except A2ClientStopped:
                    raise
                except OSError:
                    self._interruptible_wait(
                        backoff,
                        pending=True,
                    )
                    backoff = min(
                        self.config.reconnect_max_seconds,
                        backoff
                        * self.config.reconnect_multiplier,
                    )
                    continue

            try:
                sock.sendall(frame)
            except OSError:
                self._drop_connection()
                self._interruptible_wait(
                    backoff,
                    pending=True,
                )
                backoff = min(
                    self.config.reconnect_max_seconds,
                    backoff
                    * self.config.reconnect_multiplier,
                )
                continue

            try:
                ack = self._read_ack(sock)
            except A2ClientStopped:
                self._drop_connection()
                raise
            except A2ClientProtocolError:
                self._drop_connection()
                raise
            except (
                EOFError,
                OSError,
                TimeoutError,
            ):
                self._drop_connection()
                self._interruptible_wait(
                    backoff,
                    pending=True,
                )
                backoff = min(
                    self.config.reconnect_max_seconds,
                    backoff
                    * self.config.reconnect_multiplier,
                )
                continue

            action = self._classify_ack(ack)

            if action == "persisted":
                return ack

            self._drop_connection()
            self._interruptible_wait(
                backoff,
                pending=True,
            )
            backoff = min(
                self.config.reconnect_max_seconds,
                backoff
                * self.config.reconnect_multiplier,
            )

    def run_binary_stream(
        self,
        stream: BinaryIO,
    ) -> int:
        """Read exactly one producer JSONL event per acknowledged cycle."""
        delivered = 0

        while True:
            if self._stop_event.is_set():
                return delivered

            try:
                line = stream.readline(
                    self.config.max_frame_bytes * 4 + 2
                )
            except UnicodeError as exc:
                raise A2ClientProtocolError(
                    "producer stream decode failure"
                ) from exc

            if line == b"":
                return delivered

            if not isinstance(line, bytes):
                raise A2ClientProtocolError(
                    "producer stream must be binary"
                )

            if not line.endswith(b"\n"):
                raise A2ClientProtocolError(
                    "producer event is not LF framed"
                )

            frame = line[:-1]

            if frame.endswith(b"\r"):
                frame = frame[:-1]

            if not frame:
                raise A2ClientProtocolError(
                    "empty producer frame"
                )

            try:
                text = frame.decode(
                    "utf-8",
                    errors="strict",
                )
            except UnicodeDecodeError as exc:
                raise A2ClientProtocolError(
                    "producer frame is not UTF-8"
                ) from exc

            try:
                value = json.loads(text)
            except json.JSONDecodeError as exc:
                raise A2ClientProtocolError(
                    "producer frame is not JSON"
                ) from exc

            self.send_event(value)
            delivered += 1


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "GuToChat APRS-A2 producer-side AF_UNIX client"
        )
    )

    parser.add_argument(
        "--socket",
        default=str(DEFAULT_SOCKET_PATH),
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=1.0,
    )
    parser.add_argument(
        "--ack-timeout",
        type=float,
        default=5.0,
    )
    parser.add_argument(
        "--reconnect-initial",
        type=float,
        default=0.25,
    )
    parser.add_argument(
        "--reconnect-max",
        type=float,
        default=2.0,
    )
    parser.add_argument(
        "--reconnect-multiplier",
        type=float,
        default=2.0,
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        config = A2ClientConfig(
            socket_path=Path(args.socket),
            connect_timeout_seconds=args.connect_timeout,
            ack_timeout_seconds=args.ack_timeout,
            reconnect_initial_seconds=args.reconnect_initial,
            reconnect_max_seconds=args.reconnect_max,
            reconnect_multiplier=args.reconnect_multiplier,
        )
    except ValueError as exc:
        print(
            "A2_CLIENT_CONFIG_ERROR=" + str(exc),
            file=sys.stderr,
        )
        return 2

    client = A2UnixClient(config)

    try:
        client.run_binary_stream(
            sys.stdin.buffer
        )
        return 0
    except A2ClientStopped as exc:
        return 4 if exc.pending else 0
    except A2ClientProtocolError as exc:
        print(
            "A2_CLIENT_PROTOCOL_ERROR=" + str(exc),
            file=sys.stderr,
        )
        return 3
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
