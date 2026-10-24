#!/usr/bin/env python3
"""Privacy-conscious diagnostic bundle for GuToChat.

The bundle contains versions, service/queue state, database health and selected
warning/error log lines. Message bodies, raw radio payloads and contact aliases
are deliberately omitted.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

APP_VERSION = "2.5.0-beta5"

_SENSITIVE_KEYS = {
    "password",
    "passphrase",
    "psk",
    "private_key",
    "secret",
    "token",
}


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def api_call(host: str, port: int, request: dict[str, Any], timeout: float = 2.5) -> dict[str, Any]:
    data = (json.dumps(request, ensure_ascii=False) + "\n").encode("utf-8")
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(data)
        response = json.loads(sock.makefile("rb").readline().decode("utf-8"))
    if not response.get("ok"):
        raise RuntimeError(str(response.get("error", "Ukjent API-feil")))
    return response


def _run(command: list[str], timeout: float = 5.0) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return completed.returncode, completed.stdout.strip()
    except FileNotFoundError:
        return 127, "kommando ikke installert"
    except subprocess.TimeoutExpired:
        return 124, "kommando tidsavbrutt"
    except Exception as exc:  # pragma: no cover - defensive diagnostic path
        return 1, f"{type(exc).__name__}: {exc}"


def _temperature() -> str:
    thermal = Path("/sys/class/thermal/thermal_zone0/temp")
    try:
        return f"{int(thermal.read_text().strip()) / 1000:.1f} °C"
    except Exception:
        code, output = _run(["vcgencmd", "measure_temp"])
        return output if code == 0 else "ukjent"


def _throttled() -> str:
    code, output = _run(["vcgencmd", "get_throttled"])
    return output if code == 0 else "ukjent"


def _sanitize_config(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if any(marker in lowered for marker in _SENSITIVE_KEYS):
        return "<skjult>"
    if isinstance(value, dict):
        return {str(k): _sanitize_config(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_config(item, key) for item in value]
    if lowered in {"contacts_file", "database", "serial_port"}:
        return str(value)
    return value


def sanitize_log_line(line: str) -> str:
    """Remove message/control payloads while retaining useful transport facts."""
    clean = line.rstrip()
    clean = re.sub(r"~(?:LC2|L3)\|.*$", "<kontrollinnhold skjult>", clean)
    clean = re.sub(
        r"(Sendt UID=.*?\(forsøk \d+\):)\s*.*$",
        r"\1 <innhold skjult>",
        clean,
    )
    clean = re.sub(
        r"(Mottatt UID=.*?RSSI -?\d+ dBm:)\s*.*$",
        r"\1 <innhold skjult>",
        clean,
    )
    clean = re.sub(
        r"(Meshtastic (?:mottatt fra|sendt til).*?:)\s*.*$",
        r"\1 <innhold skjult>",
        clean,
        flags=re.IGNORECASE,
    )
    clean = re.sub(
        r"(For kort mottakspakke:)\s*[0-9a-fA-F]+$",
        r"\1 <råpakke skjult>",
        clean,
    )
    clean = re.sub(r"(tekst=)[^,}\]]+", r"\1<skjult>", clean, flags=re.IGNORECASE)
    return clean


def _service_info(services: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for service in services:
        _, active = _run(["systemctl", "is-active", service])
        _, enabled = _run(["systemctl", "is-enabled", service])
        code, logs = _run(
            [
                "journalctl",
                "-u",
                service,
                "--since",
                "-30 minutes",
                "--no-pager",
                "-p",
                "warning",
                "-n",
                "120",
            ],
            timeout=8.0,
        )
        lines = [sanitize_log_line(line) for line in logs.splitlines() if line.strip()]
        result[service] = {
            "active": active,
            "enabled": enabled,
            "warning_log_available": code == 0,
            "warning_log": lines,
        }
    return result


def _database_summary(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file(),
        "size_bytes": path.stat().st_size if path.is_file() else 0,
        "integrity": "database mangler",
        "tables": {},
        "outbox": {},
    }
    if not path.is_file():
        return result
    try:
        con = sqlite3.connect(path, timeout=10)
        con.row_factory = sqlite3.Row
        integrity_rows = [str(row[0]) for row in con.execute("PRAGMA integrity_check")]
        result["integrity"] = "; ".join(integrity_rows[:10])
        tables = [
            str(row[0])
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            if not str(row[0]).startswith("sqlite_")
        ]
        for table in tables:
            try:
                result["tables"][table] = int(
                    con.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                )
            except sqlite3.DatabaseError:
                result["tables"][table] = "feil"
        if "outbox" in tables:
            rows = con.execute(
                """
                SELECT traffic_class, state, COUNT(*) AS count,
                       MAX(attempts) AS max_attempts,
                       MIN(created_at) AS oldest_created
                  FROM outbox
                 GROUP BY traffic_class, state
                 ORDER BY traffic_class, state
                """
            ).fetchall()
            result["outbox"]["groups"] = [dict(row) for row in rows]
            queue_rows = [
                dict(row)
                for row in con.execute(
                    """
                    SELECT message_uid, destination, state, attempts,
                           next_attempt_epoch, expires_epoch, last_attempt_epoch,
                           last_error, created_at, updated_at, traffic_class,
                           control_command, control_route, control_request_id,
                           control_group, max_attempts
                      FROM outbox
                     ORDER BY created_at
                     LIMIT 250
                    """
                )
            ]
            for item in queue_rows:
                item["last_error"] = sanitize_log_line(str(item.get("last_error", "")))
            result["outbox"]["rows_without_text"] = queue_rows
        con.close()
    except Exception as exc:
        result["integrity"] = f"{type(exc).__name__}: {exc}"
    return result


def _api_statuses(config: dict[str, Any]) -> dict[str, Any]:
    targets: list[tuple[str, str, int]] = [
        (
            "waveshare",
            str(config.get("api_host", "127.0.0.1")),
            int(config.get("api_port", 8765)),
        )
    ]
    for item in config.get("meshtastic_radios", []):
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        label = str(item.get("route_key") or item.get("key") or item.get("label") or "mesh")
        targets.append(
            (label, str(item.get("api_host", "127.0.0.1")), int(item["api_port"]))
        )
    result: dict[str, Any] = {}
    for label, host, port in targets:
        try:
            result[label] = api_call(host, port, {"command": "status"})["status"]
        except Exception as exc:
            result[label] = {"online": False, "error": f"{type(exc).__name__}: {exc}"}
    return result


def collect_diagnostics(config: dict[str, Any], *, role: str | None = None) -> dict[str, Any]:
    database = Path(str(config.get("database", "")))
    services = ["lorad-v2.service"]
    if role == "base" or config.get("meshtastic_radios"):
        services.extend(["meshbridge-v2.service", "meshbridge433-v2.service"])
        for item in config.get("meshtastic_radios", []):
            if not isinstance(item, dict) or not item.get("enabled", True):
                continue
            route = str(item.get("route_key") or item.get("key") or "").strip().lower()
            try:
                api_port = int(item.get("api_port", 0))
            except (TypeError, ValueError):
                api_port = 0
            if route == "mesh433f" or api_port == 8768:
                services.append("meshbridge433f-v2.service")
                break
    disk = shutil.disk_usage(database.parent if database.parent.exists() else Path.home())
    return {
        "generated_at": now_iso(),
        "diagnostic_format": 1,
        "app_version": APP_VERSION,
        "role": role or "ukjent",
        "system": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "temperature": _temperature(),
            "throttled": _throttled(),
            "uptime_seconds": int(time.monotonic()),
            "disk_total_bytes": disk.total,
            "disk_used_bytes": disk.used,
            "disk_free_bytes": disk.free,
        },
        "config_without_secrets": _sanitize_config(config),
        "api_status": _api_statuses(config),
        "database": _database_summary(database),
        "services": _service_info(services),
        "privacy_note": (
            "Meldingstekst, radiopayload, råpakker og kontaktalias er ikke tatt med. "
            "Logglinjer er filtrert før eksport."
        ),
    }


def write_bundle(destination: Path, config: dict[str, Any], *, role: str | None = None) -> Path:
    destination = destination.expanduser()
    if destination.suffix.lower() != ".zip":
        destination = destination.with_suffix(".zip")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = collect_diagnostics(config, role=role)
    with tempfile.TemporaryDirectory(prefix="lorachat-diagnostics-") as tmp:
        root = Path(tmp)
        json_path = root / "diagnostics.json"
        text_path = root / "README.txt"
        json_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        text_path.write_text(
            "GuToChat diagnostikkpakke\n"
            f"Opprettet: {payload['generated_at']}\n"
            f"Versjon: {payload['app_version']}\n\n"
            f"{payload['privacy_note']}\n",
            encoding="utf-8",
        )
        temporary = destination.with_name(destination.name + ".tmp")
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(json_path, json_path.name)
            archive.write(text_path, text_path.name)
        os.replace(temporary, destination)
    return destination
