#!/usr/bin/env python3
"""Headless receive-only APRS-IS runtime for GuToChat/GuToMap.

A1H is intentionally narrow: this process may receive APRS-IS and write only
GuToChat's separate APRS SQLite database.  It contains no APRS transmit API and
no Meshtastic/cross-network forwarding path.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import threading
import time
from typing import Any

from aprs_a2_ipc import A2IpcError, A2UnixIngressServer, build_a2_ipc_config
from aprs_ingest_owner import AprsIngestOwnershipError
from aprs_live_runtime import AprsLiveRuntime, build_aprs_live_runtime_from_config


DEFAULT_CONFIG = Path.home() / ".config" / "lorachat-v2" / "config.json"
STATUS_SCHEMA_VERSION = 1
APRS_TRANSMIT = False
CROSS_NETWORK_ROUTING = False
RECEIVE_ONLY = True


def _require_explicit_bool(config: dict[str, Any], key: str, expected: bool) -> None:
    if key not in config or not isinstance(config[key], bool):
        raise ValueError(f"Headless APRS requires explicit boolean {key}")
    if config[key] is not expected:
        raise ValueError(f"Unsafe headless APRS policy: {key}")


def validate_headless_policy(config: dict[str, Any]) -> None:
    """Fail closed unless every A1H safety/ownership policy is explicit."""
    _require_explicit_bool(config, "map_aprs_headless_enabled", True)
    _require_explicit_bool(config, "map_aprs_live_enabled", True)
    _require_explicit_bool(config, "map_aprs_live_continuous", True)
    _require_explicit_bool(config, "map_aprs_receive_only", True)
    _require_explicit_bool(config, "map_aprs_transmit_enabled", False)
    _require_explicit_bool(config, "map_aprs_cross_network_routing_enabled", False)

    if APRS_TRANSMIT is not False or CROSS_NETWORK_ROUTING is not False or RECEIVE_ONLY is not True:
        raise RuntimeError("Compiled APRS safety policy is inconsistent")


def headless_status_path(config: dict[str, Any], aprs_database_path: Path) -> Path:
    raw = str(config.get("map_aprs_headless_status_file", "")).strip()
    if raw:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            raise ValueError("APRS headless status path must be absolute")
        return path.resolve()
    db = Path(aprs_database_path).expanduser().resolve()
    return db.with_name(db.name + ".headless-status.json")


def _safe_status_payload(runtime: AprsLiveRuntime, *, running: bool) -> dict[str, Any]:
    snapshot = runtime.snapshot()
    diagnostics = snapshot.diagnostics
    return {
        "schema_version": STATUS_SCHEMA_VERSION,
        "updated_epoch": time.time(),
        "owner_role": "headless",
        "running": bool(running),
        "connected": bool(running and snapshot.state == "running"),
        "state": snapshot.state,
        "error": snapshot.error,
        "stats": dict(snapshot.stats),
        "diagnostics": {
            "session_count": int(diagnostics.get("session_count", 0)),
            "reconnect_count": int(diagnostics.get("reconnect_count", 0)),
            "session_failures": int(diagnostics.get("session_failures", 0)),
            "connection_failures": int(diagnostics.get("connection_failures", 0)),
            "consecutive_failures": int(diagnostics.get("consecutive_failures", 0)),
            "current_backoff_seconds": float(diagnostics.get("current_backoff_seconds", 0.0)),
            "last_success_epoch": diagnostics.get("last_success_epoch"),
            "last_packet_epoch": diagnostics.get("last_packet_epoch"),
            "shutdown_clean": bool(diagnostics.get("shutdown_clean", True)),
        },
        "policy": {
            "receive_only": RECEIVE_ONLY,
            "aprs_transmit": APRS_TRANSMIT,
            "cross_network_routing": CROSS_NETWORK_ROUTING,
        },
    }


def write_headless_status(path: Path, payload: dict[str, Any]) -> None:
    """Atomically write privacy-safe machine-readable status with mode 0600."""
    target = Path(path).expanduser()
    if not target.is_absolute():
        raise ValueError("APRS headless status path must be absolute")
    target = Path(os.path.abspath(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        mode = target.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise ValueError("APRS headless status target must be a regular file")
    except FileNotFoundError:
        pass

    fd, tmp_name = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp", dir=target.parent)
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", closefd=True) as handle:
            json.dump(payload, handle, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
        os.chmod(target, 0o600)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def read_headless_status(path: Path, *, max_age_seconds: float = 5.0) -> dict[str, Any] | None:
    """Read fresh headless status without treating stale files as active."""
    target = Path(path).expanduser()
    try:
        if target.is_symlink() or not target.is_file():
            return None
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("schema_version") != STATUS_SCHEMA_VERSION:
        return None
    updated = data.get("updated_epoch")
    if not isinstance(updated, (int, float)):
        return None
    if time.time() - float(updated) > max(1.0, float(max_age_seconds)):
        return None
    return data


def build_headless_runtime_from_config(
    config: dict[str, Any],
    *,
    connector=None,
) -> tuple[AprsLiveRuntime, Path]:
    validate_headless_policy(config)
    if "database" not in config:
        raise ValueError("Headless APRS requires product database path for isolation guard")
    if "map_aprs_database" not in config:
        raise ValueError("Headless APRS requires explicit map_aprs_database")

    product_db = Path(str(config["database"])).expanduser()
    aprs_db = Path(str(config["map_aprs_database"])).expanduser()
    if not product_db.is_absolute() or not aprs_db.is_absolute():
        raise ValueError("Headless APRS database paths must be absolute")

    runtime = build_aprs_live_runtime_from_config(
        config,
        product_database_path=product_db,
        aprs_database_path=aprs_db,
        connector=connector,
        owner_role="headless",
    )
    if runtime is None:  # Defensive; policy above requires live_enabled=True.
        raise ValueError("Headless APRS live runtime is disabled")
    return runtime, headless_status_path(config, aprs_db)


def build_headless_a2_server_from_config(
    config: dict[str, Any],
    runtime: AprsLiveRuntime,
) -> A2UnixIngressServer | None:
    """Build optional A2 ingress without opening a socket."""
    ipc_config = build_a2_ipc_config(config)

    if not ipc_config.enabled:
        return None

    return A2UnixIngressServer(
        ipc_config,
        runtime.submit_a2_event,
    )


class HeadlessAprsService:
    def __init__(
        self,
        runtime: AprsLiveRuntime,
        status_path: Path,
        *,
        a2_server: A2UnixIngressServer | None = None,
        status_interval_seconds: float = 1.0,
    ) -> None:
        interval = float(status_interval_seconds)
        if not 0.05 <= interval <= 60.0:
            raise ValueError("APRS status interval must be within 0.05..60 seconds")
        self.runtime = runtime
        self.status_path = Path(status_path)
        self.a2_server = a2_server
        self.status_interval_seconds = interval

    def run(self, stop_event: threading.Event) -> int:
        self.runtime.start()

        if self.a2_server is not None:
            try:
                self.a2_server.start()
            except BaseException:
                if self.runtime.running:
                    self.runtime.stop()
                raise

        write_headless_status(
            self.status_path,
            _safe_status_payload(self.runtime, running=self.runtime.running),
        )

        a2_failed = False

        while self.runtime.running and not stop_event.wait(self.status_interval_seconds):
            if self.a2_server is not None and not self.a2_server.running:
                a2_failed = True
                break

            write_headless_status(
                self.status_path,
                _safe_status_payload(self.runtime, running=True),
            )

        a2_clean = True

        if self.a2_server is not None:
            try:
                a2_clean = self.a2_server.stop()
            except Exception:
                a2_clean = False

        runtime_clean = True

        if self.runtime.running:
            runtime_clean = self.runtime.stop()

        if a2_failed or not a2_clean or not runtime_clean:
            write_headless_status(
                self.status_path,
                _safe_status_payload(
                    self.runtime,
                    running=self.runtime.running,
                ),
            )
            return 4

        snapshot = self.runtime.snapshot()
        write_headless_status(
            self.status_path,
            _safe_status_payload(self.runtime, running=False),
        )
        return 0 if snapshot.state in {"stopped", "complete"} and not snapshot.error else 4


def _load_config(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config.json must contain a JSON object")
    return data


def _apply_cli_mode(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    result = dict(config)
    if bool(getattr(args, "local_rf_only", False)):
        # The local A2 ingest owner must never initiate APRS-IS.  Keep every
        # other receive-only / single-writer policy unchanged.
        result["map_aprs_is_receive_enabled"] = False
    return result


def _run_command(args: argparse.Namespace) -> int:
    config = _apply_cli_mode(_load_config(Path(args.config).expanduser()), args)
    runtime, status_path = build_headless_runtime_from_config(config)
    a2_server = build_headless_a2_server_from_config(
        config,
        runtime,
    )
    service = HeadlessAprsService(
        runtime,
        status_path,
        a2_server=a2_server,
        status_interval_seconds=args.status_interval,
    )
    stop_event = threading.Event()

    def request_stop(_signum, _frame) -> None:
        stop_event.set()

    previous: dict[int, Any] = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, request_stop)
    try:
        return service.run(stop_event)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _validate_command(args: argparse.Namespace) -> int:
    config = _apply_cli_mode(_load_config(Path(args.config).expanduser()), args)
    runtime, _status_path = build_headless_runtime_from_config(config)
    build_a2_ipc_config(config)
    result = {
        "ok": True,
        "continuous": bool(runtime.config.continuous),
        "owner_role": runtime.config.owner_role,
        "policy": {
            "receive_only": RECEIVE_ONLY,
            "aprs_transmit": APRS_TRANSMIT,
            "cross_network_routing": CROSS_NETWORK_ROUTING,
        },
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GuToChat headless receive-only APRS runtime")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run continuous headless APRS ingest")
    run.add_argument("--config", default=str(DEFAULT_CONFIG))
    run.add_argument("--status-interval", type=float, default=1.0)
    run.add_argument(
        "--local-rf-only",
        action="store_true",
        help="run the shared ingest owner with APRS-IS networking forced off",
    )
    run.set_defaults(func=_run_command)

    validate = sub.add_parser("validate", help="validate fail-closed A1H configuration")
    validate.add_argument("--config", default=str(DEFAULT_CONFIG))
    validate.add_argument(
        "--local-rf-only",
        action="store_true",
        help="validate the local-RF-only ingest-owner mode",
    )
    validate.set_defaults(func=_validate_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except AprsIngestOwnershipError:
        print("APRS_HEADLESS_ERROR=OWNERSHIP_CONFLICT", file=sys.stderr)
        return 3
    except (A2IpcError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"APRS_HEADLESS_ERROR={type(exc).__name__}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
