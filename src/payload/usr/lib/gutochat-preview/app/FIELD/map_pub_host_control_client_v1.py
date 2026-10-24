"""Unprivileged client for the root-owned host MAP-PUB ON/OFF controller."""
from __future__ import annotations
import json
import socket
from pathlib import Path
from typing import Any

DEFAULT_SOCKET_PATH = Path("/run/gutochat-map-pub-host-control/control.sock")


class HostMapPublicationControlClient:
    def __init__(self, path: str | Path = DEFAULT_SOCKET_PATH, *, timeout: float = 20.0) -> None:
        self.path = Path(path)
        self.timeout = float(timeout)
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")

    def call(self, request: dict[str, Any]) -> dict[str, Any]:
        payload = (json.dumps(dict(request), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(str(self.path))
            sock.sendall(payload)
            line = sock.makefile("rb").readline(64 * 1024)
        if not line:
            raise RuntimeError("HOST_MAP_CONTROL_EMPTY_RESPONSE")
        result = json.loads(line.decode("utf-8"))
        if not isinstance(result, dict):
            raise RuntimeError("HOST_MAP_CONTROL_INVALID_RESPONSE")
        return result

    def status(self) -> dict[str, Any]:
        return self.call({"command": "status"})

    def set_state(self, target_state: str, *, request_id: str) -> dict[str, Any]:
        return self.call({
            "command": "set_state",
            "target_state": str(target_state).strip().upper(),
            "request_id": str(request_id),
        })
