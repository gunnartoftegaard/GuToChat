#!/usr/bin/env python3
"""Lean, read-mostly operational CLI for GuToChat.

Commands:
- ``status``: one concise health summary with machine-readable JSON support.
- ``collect``: a privacy-reduced diagnostic ZIP plus SHA256 sidecar.
- ``forensics``: a read-only evidence report for unclear operational states.

The CLI never sends radio or network messages, changes services, or writes to
GuToChat's database/configuration. ``collect`` only writes its requested output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

import diagnostics
from roles import infer_role_from_config

CLI_VERSION = "0.1-dev2a"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = Path.home() / ".config" / "lorachat-v2" / "config.json"
SEVERITY = {"PASS": 0, "WARNING": 1, "FAIL": 2}
FORENSICS_FINAL_STATES = {"PASS", "FAIL", "UNKNOWN"}
FORENSICS_AREA_STATES = {"PASS", "FAIL", "UNKNOWN", "NOT-RUN", "RUNNING"}
FORENSICS_SELECTED_FILES = ("VERSION", "app/gutodiag.py", "gutodiag", "update.sh")
FORENSICS_MAX_SAMPLES = 5
FORENSICS_MAX_INTERVAL_SECONDS = 60


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def app_version() -> str:
    try:
        return (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return diagnostics.APP_VERSION


def _home_reduced(value: Any) -> str:
    text = str(value or "")
    try:
        home = str(Path.home())
        if home and text.startswith(home):
            return "~" + text[len(home) :]
    except Exception:
        pass
    return text


def _redact_text(value: Any) -> str:
    text = diagnostics.sanitize_log_line(str(value or ""))
    text = text.replace(str(Path.home()), "~")
    text = re.sub(r"(?i)\b(?:station|node|device)[_-]?id\s*[=:]\s*[^\s,;]+", "identifier=<skjult>", text)
    text = re.sub(
        r"(?i)\b(?:psk|password|passphrase|token|secret|private[_-]?key)\s*[=:]\s*[^\s,;]+",
        "secret=<skjult>",
        text,
    )
    text = re.sub(r"![0-9a-fA-F]{8}\b", "!<skjult>", text)
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<e-post skjult>", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP skjult>", text)
    text = re.sub(r"(?<![\w.])-?\d{1,3}\.\d{4,}\s*[,;/]\s*-?\d{1,3}\.\d{4,}(?![\w.])", "<koordinater skjult>", text)
    text = re.sub(r"(?<![A-Za-z0-9])(?:[A-Za-z]:\\|/)(?:[^\s:;,]+[\\/]?)+", "<bane skjult>", text)
    return text


def _load_config(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config.json må inneholde et JSON-objekt")
    return data


def _expected_services(config: dict[str, Any], role: str) -> list[str]:
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
    return services


def _service_checks(services: Iterable[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    detail: dict[str, Any] = {}
    for service in services:
        active_code, active = diagnostics._run(["systemctl", "is-active", service])
        enabled_code, enabled = diagnostics._run(["systemctl", "is-enabled", service])
        active_clean = active.strip()
        active_first_line = active_clean.splitlines()[0] if active_clean else ""
        systemd_unavailable = (
            active_code == 127
            or active_clean == "kommando ikke installert"
            or "not been booted with systemd" in active_clean
            or "Failed to connect to" in active_clean
        )
        if systemd_unavailable:
            state = "WARNING"
            message = "systemd/systemctl er ikke tilgjengelig i dette miljøet"
        elif active_clean == "active":
            state = "PASS"
            message = "active"
        else:
            state = "FAIL"
            message = active_first_line or f"systemctl exit {active_code}"
        checks.append({"name": f"service:{service}", "state": state, "message": message})
        detail[service] = {
            "active": active.strip(),
            "enabled": enabled.strip(),
            "active_exit_code": active_code,
            "enabled_exit_code": enabled_code,
        }
    return checks, detail


def _api_targets(config: dict[str, Any]) -> list[tuple[str, str, int]]:
    targets = [
        (
            "waveshare",
            str(config.get("api_host", "127.0.0.1")),
            int(config.get("api_port", 8765)),
        )
    ]
    for index, item in enumerate(config.get("meshtastic_radios", []), start=1):
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        label = str(item.get("route_key") or item.get("key") or f"mesh-{index}")
        targets.append((label, str(item.get("api_host", "127.0.0.1")), int(item["api_port"])))
    return targets


def _api_checks(config: dict[str, Any], expected_version: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    detail: dict[str, Any] = {}
    for label, host, port in _api_targets(config):
        try:
            status = diagnostics.api_call(host, port, {"command": "status"})["status"]
            service_version = str(status.get("service_version", ""))
            version_ok = not service_version or service_version == expected_version
            state = "PASS" if version_ok else "FAIL"
            message = "online"
            if not version_ok:
                message = f"tjenesteversjon {service_version!r}, forventet {expected_version!r}"
            detail[label] = {
                "host": host,
                "port": port,
                "online": True,
                "service_version": service_version,
                "radio_online": bool(status.get("radio_online", status.get("online", True))),
                "last_error": _redact_text(status.get("last_error", "")),
                "pending_acks": status.get("pending_acks"),
                "outbox_pending": status.get("outbox_pending"),
                "database_integrity": status.get("database_integrity"),
                "protocol": status.get("protocol"),
            }
        except Exception as exc:
            state = "FAIL"
            message = f"{type(exc).__name__}: {_redact_text(exc)}"
            detail[label] = {"host": host, "port": port, "online": False, "error": message}
        checks.append({"name": f"api:{label}", "state": state, "message": message})
    return checks, detail


def _database_check(config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    path = Path(str(config.get("database", ""))).expanduser()
    detail: dict[str, Any] = {
        "path": _home_reduced(path),
        "exists": path.is_file(),
        "size_bytes": path.stat().st_size if path.is_file() else 0,
        "quick_check": "database mangler",
        "tables": {},
    }
    if not path.is_file():
        return {"name": "database", "state": "FAIL", "message": "databasefilen mangler"}, detail
    try:
        uri = f"file:{path.resolve().as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as con:
            quick = [str(row[0]) for row in con.execute("PRAGMA quick_check")]
            detail["quick_check"] = "; ".join(quick[:10])
            tables = [
                str(row[0])
                for row in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                if not str(row[0]).startswith("sqlite_")
            ]
            for table in tables:
                try:
                    detail["tables"][table] = int(con.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
                except sqlite3.DatabaseError:
                    detail["tables"][table] = "feil"
        if detail["quick_check"].lower() == "ok":
            return {"name": "database", "state": "PASS", "message": "SQLite quick_check=ok"}, detail
        return {"name": "database", "state": "FAIL", "message": f"SQLite quick_check={detail['quick_check']}"}, detail
    except Exception as exc:
        detail["quick_check"] = f"{type(exc).__name__}: {_redact_text(exc)}"
        return {"name": "database", "state": "FAIL", "message": detail["quick_check"]}, detail


def _map_check(config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    configured: list[Path] = []
    for key in ("offline_map_directory", "offline_map_path"):
        raw = str(config.get(key, "")).strip()
        if raw:
            configured.append(Path(raw).expanduser())
    if not configured:
        return {"name": "offline-map", "state": "WARNING", "message": "ingen kartbane konfigurert"}, {"configured": []}
    existing = [path for path in configured if path.exists()]
    detail = {
        "configured": [_home_reduced(path) for path in configured],
        "existing": [_home_reduced(path) for path in existing],
    }
    if existing:
        return {"name": "offline-map", "state": "PASS", "message": f"{len(existing)} konfigurert bane(r) finnes"}, detail
    return {"name": "offline-map", "state": "FAIL", "message": "konfigurert kartbane finnes ikke"}, detail


def _overall(checks: list[dict[str, Any]]) -> str:
    return max((str(check["state"]) for check in checks), key=lambda value: SEVERITY[value], default="WARNING")


def build_status(config_path: Path) -> dict[str, Any]:
    expected_version = app_version()
    checks: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "generated_at": now_iso(),
        "gutodiag_version": CLI_VERSION,
        "app_version": expected_version,
        "config_path": _home_reduced(config_path),
        "role": "ukjent",
        "checks": checks,
        "details": {},
    }
    try:
        config = _load_config(config_path)
        role = infer_role_from_config(config)
        result["role"] = role
        checks.append({"name": "config", "state": "PASS", "message": "gyldig JSON og rolle"})
    except Exception as exc:
        checks.append({"name": "config", "state": "FAIL", "message": f"{type(exc).__name__}: {_redact_text(exc)}"})
        result["overall"] = "FAIL"
        return result

    database_check, database_detail = _database_check(config)
    checks.append(database_check)
    service_checks, service_detail = _service_checks(_expected_services(config, role))
    checks.extend(service_checks)
    api_checks, api_detail = _api_checks(config, expected_version)
    checks.extend(api_checks)
    map_check, map_detail = _map_check(config)
    checks.append(map_check)

    result["details"] = {
        "database": database_detail,
        "services": service_detail,
        "api": api_detail,
        "offline_map": map_detail,
    }
    result["overall"] = _overall(checks)
    return result



def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_metadata_name(value: Any, *, kind: str = "item") -> str:
    """Return a useful basename without exposing sensitive identifiers."""
    name = Path(str(value or "")).name
    lowered = name.lower()
    sensitive_markers = (
        "password", "passphrase", "secret", "token", "private", "psk",
        "message", "contact", "position", "coordinate", "station", "node",
        "device", "callsign", "hostname", "email",
    )
    suspicious = (
        not name
        or any(marker in lowered for marker in sensitive_markers)
        or bool(re.search(r"![0-9a-fA-F]{8}\b", name))
        or bool(re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", name))
        or bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", name))
        or bool(re.search(r"[A-Fa-f0-9]{24,}", name))
    )
    if suspicious:
        token = hashlib.sha256(name.encode("utf-8", errors="replace")).hexdigest()[:12]
        suffix = Path(name).suffix[:12] if name else ""
        return f"{kind}-redacted-{token}{suffix}"
    return re.sub(r"[^A-Za-z0-9._+-]", "_", name)[:160]


def _redacted_error(exc: BaseException, *, subject: str) -> str:
    if isinstance(exc, FileNotFoundError):
        return f"{subject} mangler"
    if isinstance(exc, json.JSONDecodeError):
        return f"{subject} inneholder ugyldig JSON"
    if isinstance(exc, PermissionError):
        return f"mangler lesetilgang til {subject}"
    return f"{type(exc).__name__}: {_redact_text(exc)}"


def _forensics_area(
    name: str,
    state: str,
    message: str,
    details: dict[str, Any] | list[Any] | None = None,
) -> dict[str, Any]:
    if state not in FORENSICS_AREA_STATES:
        raise ValueError(f"ugyldig forensics-status: {state}")
    result: dict[str, Any] = {
        "name": name,
        "state": state,
        "message": _redact_text(message),
    }
    if details is not None:
        result["details"] = details
    return result


def _forensics_overall(areas: list[dict[str, Any]]) -> str:
    states = {str(area.get("state", "UNKNOWN")) for area in areas}
    if "FAIL" in states:
        return "FAIL"
    if "UNKNOWN" in states or "RUNNING" in states:
        return "UNKNOWN"
    if "PASS" in states:
        return "PASS"
    return "UNKNOWN"


def _selected_file_identities(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    identities: list[dict[str, Any]] = []
    errors: list[str] = []
    for relative in FORENSICS_SELECTED_FILES:
        path = root / relative
        try:
            mode = path.lstat().st_mode
            if path.is_symlink() or not stat.S_ISREG(mode):
                errors.append(f"{relative}: ikke regulær fil")
                continue
            identities.append(
                {
                    "path": relative,
                    "size_bytes": path.stat().st_size,
                    "sha256": _sha256_file(path),
                }
            )
        except OSError:
            errors.append(f"{relative}: mangler eller kan ikke leses")
    return identities, errors


def _installation_identity_area(config: dict[str, Any], role: str) -> dict[str, Any]:
    identities, errors = _selected_file_identities(PROJECT_ROOT)
    installed_version = app_version()
    declared_version = str(config.get("app_version", "")).strip()
    state = "FAIL" if errors else "PASS"
    message = "; ".join(errors) if errors else (
        "installert VERSION, rolle og utvalgte filidentiteter er konsistente; "
        "config app_version behandles som bevart, ikke-autoritativ metadata"
    )
    return _forensics_area(
        "installation-identity",
        state,
        message,
        {
            "installed_version": installed_version,
            "declared_config_version": declared_version,
            "config_version_authoritative": False,
            "role": role,
            "managed_files": identities,
            "identifiers_omitted": True,
        },
    )


def _candidate_tree_violations(root: Path) -> list[str]:
    violations: list[str] = []
    try:
        root_mode = root.lstat().st_mode
    except OSError:
        return ["kandidatrot mangler eller kan ikke leses"]
    if root.is_symlink() or not stat.S_ISDIR(root_mode):
        return ["kandidatrot er ikke en regulær katalog"]
    for parent, dirs, files in os.walk(root, followlinks=False):
        parent_path = Path(parent)
        for name in list(dirs):
            path = parent_path / name
            try:
                mode = path.lstat().st_mode
            except OSError:
                violations.append("uleselig katalogoppføring")
                dirs.remove(name)
                continue
            if path.is_symlink() or not stat.S_ISDIR(mode):
                violations.append(f"ikke-regulær katalog: {_safe_metadata_name(name, kind='candidate')}" )
                dirs.remove(name)
        for name in files:
            path = parent_path / name
            try:
                mode = path.lstat().st_mode
            except OSError:
                violations.append("uleselig filoppføring")
                continue
            if path.is_symlink() or not stat.S_ISREG(mode):
                violations.append(f"ikke-regulær fil: {_safe_metadata_name(name, kind='candidate')}")
        if len(violations) >= 20:
            break
    return violations[:20]


def _candidate_area(candidate_root: Path | None) -> dict[str, Any]:
    if candidate_root is None:
        return _forensics_area("candidate", "NOT-RUN", "ingen kandidatrot oppgitt")
    candidate_root = candidate_root.expanduser()
    if not candidate_root.exists():
        return _forensics_area("candidate", "FAIL", "eksplisitt kandidatrot mangler")
    violations = _candidate_tree_violations(candidate_root)
    candidate_version_path = candidate_root / "VERSION"
    try:
        candidate_version_raw = candidate_version_path.read_text(encoding="utf-8").strip()
    except Exception as exc:
        return _forensics_area("candidate", "FAIL", _redacted_error(exc, subject="kandidatens VERSION"))
    candidate_version_safe = bool(re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,79}", candidate_version_raw))
    candidate_version = candidate_version_raw if candidate_version_safe else "<ugyldig eller skjult>"
    installed_version = app_version()
    identities, identity_errors = _selected_file_identities(candidate_root)
    installed_identities, installed_errors = _selected_file_identities(PROJECT_ROOT)
    installed_by_name = {item["path"]: item for item in installed_identities}
    comparisons: list[dict[str, Any]] = []
    mismatches: list[str] = []
    for item in identities:
        installed = installed_by_name.get(str(item["path"]))
        match = bool(installed and installed.get("sha256") == item.get("sha256"))
        comparisons.append(
            {
                "path": item["path"],
                "size_bytes": item["size_bytes"],
                "sha256": item["sha256"],
                "matches_installed": match,
            }
        )
        if not match:
            mismatches.append(str(item["path"]))
    reasons: list[str] = []
    reasons.extend(violations)
    reasons.extend(identity_errors)
    reasons.extend(installed_errors)
    if not candidate_version_safe:
        reasons.append("kandidatens VERSION har ugyldig format")
    elif candidate_version != installed_version:
        reasons.append("kandidatversjon avviker fra installert produktversjon")
    if mismatches:
        reasons.append("filidentitet avviker: " + ", ".join(sorted(mismatches)))
    state = "FAIL" if reasons else "PASS"
    return _forensics_area(
        "candidate",
        state,
        "; ".join(reasons) if reasons else "kandidatens versjon og utvalgte filidentiteter samsvarer",
        {
            "candidate_version": candidate_version,
            "files": comparisons,
            "special_entry_count": len(violations),
            "root_path_omitted": True,
        },
    )


def _systemd_unavailable(code: int, output: str) -> bool:
    clean = output.strip().lower()
    return (
        code == 127
        or clean == "kommando ikke installert"
        or "not been booted with systemd" in clean
        or "failed to connect to" in clean
        or "system has not been booted" in clean
    )


def _forensics_services_area(role: str) -> dict[str, Any]:
    expectations = {
        "lorad-v2.service": (True, True),
        "meshbridge-v2.service": (role == "base", role == "base"),
        "meshbridge433-v2.service": (role == "base", role == "base"),
    }
    details: dict[str, Any] = {}
    failures: list[str] = []
    unavailable = False
    for service, (expect_active, expect_enabled) in expectations.items():
        active_code, active_output = diagnostics._run(["systemctl", "is-active", service])
        enabled_code, enabled_output = diagnostics._run(["systemctl", "is-enabled", service])
        active = active_output.strip().splitlines()[0] if active_output.strip() else ""
        enabled = enabled_output.strip().splitlines()[0] if enabled_output.strip() else ""
        if _systemd_unavailable(active_code, active_output) or _systemd_unavailable(enabled_code, enabled_output):
            unavailable = True
        else:
            active_ok = active == "active" if expect_active else active in {"inactive", "failed", "unknown"}
            enabled_ok = enabled == "enabled" if expect_enabled else enabled in {"disabled", "masked", "static", "indirect", "not-found"}
            if not active_ok or not enabled_ok:
                failures.append(service)
        details[service] = {
            "active": _redact_text(active),
            "enabled": _redact_text(enabled),
            "expected_active": expect_active,
            "expected_enabled": expect_enabled,
        }
    if failures:
        return _forensics_area("services", "FAIL", "tjenesteprofil avviker: " + ", ".join(failures), details)
    if unavailable:
        return _forensics_area("services", "UNKNOWN", "systemd/systemctl er ikke tilgjengelig; tjenestestatus kan ikke bevises", details)
    return _forensics_area("services", "PASS", "rolleavhengig tjenesteprofil er konsistent", details)


def _safe_api_label(label: str, index: int) -> str:
    candidate = _safe_metadata_name(label, kind=f"api-{index}")
    if candidate.startswith(f"api-{index}-redacted"):
        return f"api-{index}"
    return candidate


def _forensics_api_area(config: dict[str, Any], expected_version: str) -> dict[str, Any]:
    details: dict[str, Any] = {}
    failures: list[str] = []
    for index, (label, host, port) in enumerate(_api_targets(config), start=1):
        safe_label = _safe_api_label(label, index)
        try:
            response = diagnostics.api_call(host, port, {"command": "status"})
            status_data = response["status"]
            service_version = str(status_data.get("service_version", ""))
            online = bool(status_data.get("radio_online", status_data.get("online", True)))
            last_error = _redact_text(status_data.get("last_error", ""))
            if service_version and service_version != expected_version:
                failures.append(f"{safe_label}: feil tjenesteversjon")
            if not online:
                failures.append(f"{safe_label}: offline")
            if last_error:
                failures.append(f"{safe_label}: last_error")
            details[safe_label] = {
                "local_port": int(port),
                "host_omitted": True,
                "service_version": service_version,
                "online": online,
                "last_error": last_error,
                "protocol": status_data.get("protocol"),
            }
        except Exception as exc:
            failures.append(f"{safe_label}: utilgjengelig")
            details[safe_label] = {
                "local_port": int(port),
                "host_omitted": True,
                "online": False,
                "error": _redacted_error(exc, subject="lokalt API"),
            }
    if failures:
        return _forensics_area("api", "FAIL", "; ".join(failures), details)
    return _forensics_area("api", "PASS", "forventede lokale API-er svarer konsistent", details)


def _sqlite_quick_check(path: Path) -> tuple[str, str]:
    if not path.is_file() or path.is_symlink():
        return "FAIL", "databasekopi mangler eller er ikke regulær fil"
    try:
        uri = f"file:{path.resolve().as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as con:
            con.execute("PRAGMA query_only=ON")
            rows = [str(row[0]) for row in con.execute("PRAGMA quick_check")]
        result = "; ".join(rows[:10])
        return ("PASS", "ok") if result.lower() == "ok" else ("FAIL", result)
    except Exception as exc:
        return "FAIL", _redacted_error(exc, subject="databasekopi")


def _database_area(config: dict[str, Any]) -> dict[str, Any]:
    check, detail = _database_check(config)
    state = "PASS" if check["state"] == "PASS" else "FAIL"
    return _forensics_area("database", state, str(check["message"]), detail)


def _tree_size_bytes(root: Path) -> int:
    total = 0
    for parent, dirs, files in os.walk(root, followlinks=False):
        parent_path = Path(parent)
        dirs[:] = [name for name in dirs if not (parent_path / name).is_symlink()]
        for name in files:
            path = parent_path / name
            try:
                if path.is_file() and not path.is_symlink():
                    total += path.stat().st_size
            except OSError:
                continue
    return total


def _backup_area(root: Path | None, *, explicit: bool) -> dict[str, Any]:
    selected_root = (root or (Path.home() / "lorachat-v2-backups")).expanduser()
    if not selected_root.exists():
        state = "UNKNOWN" if explicit else "NOT-RUN"
        message = "eksplisitt backuprot mangler" if explicit else "standard backuprot finnes ikke"
        return _forensics_area("backups", state, message)
    if selected_root.is_symlink() or not selected_root.is_dir():
        return _forensics_area("backups", "UNKNOWN", "backuprot er ikke en regulær katalog")
    children = [item for item in selected_root.iterdir() if item.is_dir() and not item.is_symlink()]
    children.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    if not children:
        return _forensics_area("backups", "NOT-RUN", "ingen backupkataloger funnet")
    items: list[dict[str, Any]] = []
    incomplete = False
    for child in children[:5]:
        version_candidates = (child / "lorachat-v2" / "VERSION", child / "VERSION")
        version_path = next((path for path in version_candidates if path.is_file() and not path.is_symlink()), None)
        db_path = child / "messages.db"
        db_state, db_result = _sqlite_quick_check(db_path)
        manifest_path = child / "update-manifest.json"
        if version_path is None or db_state != "PASS" or not manifest_path.is_file() or manifest_path.is_symlink():
            incomplete = True
        version = "mangler"
        if version_path is not None:
            try:
                raw_version = version_path.read_text(encoding="utf-8").strip()[:160]
                version = raw_version if re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,79}", raw_version) else "<ugyldig eller skjult>"
                if version.startswith("<"):
                    incomplete = True
            except OSError:
                version = "uleselig"
                incomplete = True
        stat_result = child.stat()
        items.append(
            {
                "name": _safe_metadata_name(child.name, kind="backup"),
                "modified_at": datetime.fromtimestamp(stat_result.st_mtime).astimezone().isoformat(timespec="seconds"),
                "age_seconds": max(0, int(time.time() - stat_result.st_mtime)),
                "size_bytes": _tree_size_bytes(child),
                "version": version,
                "has_version": version_path is not None,
                "has_database": db_path.is_file() and not db_path.is_symlink(),
                "database_quick_check": db_result,
                "has_update_manifest": manifest_path.is_file() and not manifest_path.is_symlink(),
            }
        )
    state = "UNKNOWN" if incomplete else "PASS"
    message = "én eller flere backuper er ufullstendige" if incomplete else "nyeste backuper har komplett metadata og read-only databasekontroll"
    return _forensics_area("backups", state, message, {"items": items, "root_path_omitted": True})


def _log_area(root: Path | None, *, explicit: bool) -> dict[str, Any]:
    selected_root = (root or Path.home()).expanduser()
    if not selected_root.exists():
        state = "UNKNOWN" if explicit else "NOT-RUN"
        message = "eksplisitt loggrot mangler" if explicit else "standard loggrot finnes ikke"
        return _forensics_area("logs", state, message)
    if selected_root.is_symlink() or not selected_root.is_dir():
        return _forensics_area("logs", "UNKNOWN", "loggrot er ikke en regulær katalog")
    candidates: list[Path] = []
    special = False
    for pattern in ("gutochat*.log", "lorachat*.log", "GuToChat*.log"):
        for path in selected_root.glob(pattern):
            try:
                mode = path.lstat().st_mode
            except OSError:
                continue
            if path.is_symlink() or not stat.S_ISREG(mode):
                special = True
                continue
            candidates.append(path)
    unique = sorted(set(candidates), key=lambda item: item.stat().st_mtime, reverse=True)
    if not unique and not special:
        return _forensics_area("logs", "NOT-RUN", "ingen relevante loggfiler funnet")
    items: list[dict[str, Any]] = []
    for path in unique[:10]:
        info = path.stat()
        items.append(
            {
                "name": _safe_metadata_name(path.name, kind="log"),
                "size_bytes": info.st_size,
                "modified_at": datetime.fromtimestamp(info.st_mtime).astimezone().isoformat(timespec="seconds"),
                "sha256": _sha256_file(path),
                "content_included": False,
            }
        )
    state = "UNKNOWN" if special else "PASS"
    message = "spesialfil eller symlink ble avvist i logginventaret" if special else "loggmetadata samlet uten innholdsinkludering"
    return _forensics_area("logs", state, message, {"items": items, "root_path_omitted": True})


def _default_queue_probe(config: dict[str, Any]) -> dict[str, int]:
    counters: dict[str, int] = {}
    allowed_fields = (
        "pending_acks", "outbox_pending", "gateway_outbox_pending",
        "mesh_pending", "control_pending", "queue_pending",
    )
    for index, (_label, host, port) in enumerate(_api_targets(config), start=1):
        try:
            status_data = diagnostics.api_call(host, port, {"command": "status"})["status"]
        except Exception:
            continue
        for field in allowed_fields:
            value = status_data.get(field)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                counters[f"api-{index}:{field}"] = value
    db_path = Path(str(config.get("database", ""))).expanduser()
    if db_path.is_file() and not db_path.is_symlink():
        try:
            uri = f"file:{db_path.resolve().as_posix()}?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=5) as con:
                con.execute("PRAGMA query_only=ON")
                tables = {
                    str(row[0])
                    for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                for table in ("outbox", "gateway_outbox", "mesh_pending"):
                    if table not in tables:
                        continue
                    if table == "gateway_outbox":
                        columns = {
                            str(row[1])
                            for row in con.execute('PRAGMA table_info("gateway_outbox")')
                        }
                        if "state" in columns:
                            counters[f"database:{table}"] = int(
                                con.execute(
                                    '''
                                    SELECT COUNT(*)
                                      FROM gateway_outbox
                                     WHERE state IS NULL
                                        OR lower(trim(state)) NOT IN (
                                            'delivered', 'sent', 'failed'
                                        )
                                    '''
                                ).fetchone()[0]
                            )
                            continue
                    counters[f"database:{table}"] = int(
                        con.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                    )
        except Exception:
            pass
    return counters


def classify_queue_samples(samples: list[dict[str, int]]) -> str:
    if len(samples) < 2 or any(not sample for sample in samples):
        return "UNAVAILABLE"
    key_sets = [set(sample) for sample in samples]
    if any(keys != key_sets[0] for keys in key_sets[1:]):
        return "CHANGING"
    keys = sorted(key_sets[0])
    values = [[int(sample[key]) for key in keys] for sample in samples]
    if all(all(value == 0 for value in row) for row in values):
        return "STABLE_ZERO"
    if all(row == values[0] for row in values[1:]):
        return "STABLE_NONZERO"
    deltas = [
        current[index] - previous[index]
        for previous, current in zip(values, values[1:])
        for index in range(len(keys))
    ]
    if deltas and all(delta <= 0 for delta in deltas) and any(delta < 0 for delta in deltas):
        return "DRAINING"
    if deltas and all(delta >= 0 for delta in deltas) and any(delta > 0 for delta in deltas):
        return "GROWING"
    return "CHANGING"


def _queue_area(
    config: dict[str, Any],
    *,
    samples: int,
    interval_seconds: int,
    queue_probe: Callable[[dict[str, Any]], dict[str, int]],
    sleep_fn: Callable[[float], None],
) -> dict[str, Any]:
    snapshots: list[dict[str, Any]] = []
    raw_samples: list[dict[str, int]] = []
    try:
        for index in range(samples):
            counters = queue_probe(config)
            cleaned = {
                _safe_metadata_name(str(key), kind="counter"): int(value)
                for key, value in sorted(counters.items(), key=lambda item: str(item[0]))
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            }
            raw_samples.append(cleaned)
            snapshots.append({"sample": index + 1, "captured_at": now_iso(), "counters": cleaned})
            if index + 1 < samples:
                sleep_fn(float(interval_seconds))
    except KeyboardInterrupt:
        return _forensics_area(
            "queue-sampling",
            "UNKNOWN",
            "prøvetaking ble avbrutt; delresultat klassifiseres ikke som PASS",
            {"classification": "UNAVAILABLE", "complete": False, "samples": snapshots},
        )
    except Exception as exc:
        return _forensics_area(
            "queue-sampling",
            "UNKNOWN",
            _redacted_error(exc, subject="køprøvetaking"),
            {"classification": "UNAVAILABLE", "complete": False, "samples": snapshots},
        )
    classification = classify_queue_samples(raw_samples)
    state = "PASS" if classification in {"STABLE_ZERO", "DRAINING"} else "UNKNOWN"
    messages = {
        "STABLE_ZERO": "alle observerte køtellere er stabile på null",
        "DRAINING": "observerte køtellere drenerer uten vekst",
        "STABLE_NONZERO": "ikke-null køtellere er stabile; årsak krever videre vurdering",
        "GROWING": "køtellere vokser; aktiv trafikk eller avvik må skilles med mer bevis",
        "CHANGING": "køtellere endrer seg ulikt; sluttilstand er ikke entydig",
        "UNAVAILABLE": "tilstrekkelige kødata er ikke tilgjengelige",
    }
    return _forensics_area(
        "queue-sampling",
        state,
        messages[classification],
        {"classification": classification, "complete": True, "samples": snapshots},
    )


def build_forensics(
    config_path: Path,
    *,
    candidate_root: Path | None = None,
    backup_root: Path | None = None,
    log_root: Path | None = None,
    samples: int = 2,
    interval_seconds: int = 1,
    queue_probe: Callable[[dict[str, Any]], dict[str, int]] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if not 2 <= int(samples) <= FORENSICS_MAX_SAMPLES:
        raise ValueError(f"samples må være mellom 2 og {FORENSICS_MAX_SAMPLES}")
    if not 0 <= int(interval_seconds) <= FORENSICS_MAX_INTERVAL_SECONDS:
        raise ValueError(f"interval-seconds må være mellom 0 og {FORENSICS_MAX_INTERVAL_SECONDS}")
    config_path = config_path.expanduser()
    areas: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "generated_at": now_iso(),
        "report_format": 1,
        "gutodiag_version": CLI_VERSION,
        "app_version": app_version(),
        "config_path": _home_reduced(config_path),
        "role": "ukjent",
        "areas": areas,
        "safety": {
            "writes_performed": False,
            "services_changed": False,
            "database_changed": False,
            "radio_changed": False,
            "messages_sent": False,
            "positions_exported": False,
            "repair_attempted": False,
        },
        "privacy": {
            "message_text_omitted": True,
            "positions_omitted": True,
            "contacts_omitted": True,
            "identifiers_omitted": True,
            "secrets_omitted": True,
            "raw_config_omitted": True,
            "raw_log_content_omitted": True,
        },
    }
    try:
        config = _load_config(config_path)
        role = infer_role_from_config(config)
        result["role"] = role
        areas.append(_forensics_area("config", "PASS", "gyldig JSON og kanonisk rolle"))
    except Exception as exc:
        areas.append(_forensics_area("config", "FAIL", _redacted_error(exc, subject="konfigurasjonsfil")))
        result["overall"] = "FAIL"
        result["reasons"] = [area["message"] for area in areas if area["state"] in {"FAIL", "UNKNOWN"}]
        return result

    areas.append(_installation_identity_area(config, role))
    areas.append(_database_area(config))
    areas.append(_forensics_services_area(role))
    areas.append(_forensics_api_area(config, result["app_version"]))
    areas.append(_candidate_area(candidate_root))
    areas.append(_backup_area(backup_root, explicit=backup_root is not None))
    areas.append(_log_area(log_root, explicit=log_root is not None))
    areas.append(
        _queue_area(
            config,
            samples=int(samples),
            interval_seconds=int(interval_seconds),
            queue_probe=queue_probe or _default_queue_probe,
            sleep_fn=sleep_fn,
        )
    )
    result["overall"] = _forensics_overall(areas)
    result["reasons"] = [
        area["message"]
        for area in areas
        if area["state"] in {"FAIL", "UNKNOWN"}
    ]
    return result


def _public_config_summary(config: dict[str, Any], role: str) -> dict[str, Any]:
    return {
        "role": role,
        "configured_key_names": sorted(str(key) for key in config),
        "meshtastic_radio_count": sum(1 for item in config.get("meshtastic_radios", []) if isinstance(item, dict) and item.get("enabled", True)),
        "has_offline_map_configuration": bool(config.get("offline_map_directory") or config.get("offline_map_path")),
        "database_path": _home_reduced(config.get("database", "")),
        "serial_port": str(config.get("serial_port", "")),
        "identifiers_omitted": True,
        "secrets_omitted": True,
    }


def _system_summary(config: dict[str, Any]) -> dict[str, Any]:
    db = Path(str(config.get("database", ""))).expanduser()
    target = db.parent if db.parent.exists() else Path.home()
    disk = shutil.disk_usage(target)
    return {
        "hostname": "<skjult>",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "uptime_seconds": int(time.monotonic()),
        "temperature": diagnostics._temperature(),
        "throttled": diagnostics._throttled(),
        "disk_total_bytes": disk.total,
        "disk_used_bytes": disk.used,
        "disk_free_bytes": disk.free,
    }


def _write_sha256_sidecar(path: Path) -> Path:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    sidecar = path.with_name(path.name + ".SHA256")
    sidecar.write_text(f"{digest}  {path.name}\n", encoding="ascii")
    return sidecar


def write_privacy_reduced_bundle(destination: Path, config_path: Path) -> tuple[Path, Path]:
    config = _load_config(config_path)
    role = infer_role_from_config(config)
    status = build_status(config_path)
    payload = {
        "generated_at": now_iso(),
        "diagnostic_format": 2,
        "gutodiag_version": CLI_VERSION,
        "app_version": app_version(),
        "role": role,
        "system": _system_summary(config),
        "config_summary": _public_config_summary(config, role),
        "status": status,
        "privacy_note": (
            "Meldingstekst, rå radiopayload, kontaktalias, posisjoner, stasjonsnavn, "
            "node-ID-er, PSK, private nøkler, tokens og vertsnavn er utelatt."
        ),
    }

    destination = destination.expanduser()
    if destination.suffix.lower() != ".zip":
        destination = destination.with_suffix(".zip")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")

    with tempfile.TemporaryDirectory(prefix="gutochat-gutodiag-") as temp_dir:
        root = Path(temp_dir)
        json_path = root / "diagnostics.json"
        status_path = root / "status.json"
        readme_path = root / "README.txt"
        manifest_path = root / "manifest.sha256"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        status_path.write_text(json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        readme_path.write_text(
            "GuToChat personvernredusert diagnostikkpakke\n"
            f"Opprettet: {payload['generated_at']}\n"
            f"GuToChat-versjon: {payload['app_version']}\n"
            f"gutodiag-versjon: {CLI_VERSION}\n\n"
            f"{payload['privacy_note']}\n",
            encoding="utf-8",
        )
        manifest_lines = []
        for item in (json_path, status_path, readme_path):
            manifest_lines.append(f"{hashlib.sha256(item.read_bytes()).hexdigest()}  {item.name}")
        manifest_path.write_text("\n".join(manifest_lines) + "\n", encoding="ascii")
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for item in (json_path, status_path, readme_path, manifest_path):
                archive.write(item, item.name)
    os.replace(temporary, destination)
    sidecar = _write_sha256_sidecar(destination)
    return destination, sidecar


def _format_status_text(status: dict[str, Any]) -> str:
    lines = [
        "GuToChat status",
        f"Resultat: {status['overall']}",
        f"Versjon: {status['app_version']}",
        f"Rolle: {status['role']}",
        f"Konfigurasjon: {status['config_path']}",
        "",
    ]
    for check in status["checks"]:
        lines.append(f"[{check['state']}] {check['name']}: {check['message']}")
    return "\n".join(lines) + "\n"



def _format_forensics_text(report: dict[str, Any]) -> str:
    lines = [
        "GuToChat read-only forensics",
        f"Resultat: {report['overall']}",
        f"GuToChat-versjon: {report['app_version']}",
        f"gutodiag-versjon: {report['gutodiag_version']}",
        f"Rolle: {report['role']}",
        f"Konfigurasjon: {report['config_path']}",
        "",
    ]
    for area in report.get("areas", []):
        lines.append(f"[{area['state']}] {area['name']}: {area['message']}")
        if area["name"] == "queue-sampling" and isinstance(area.get("details"), dict):
            lines.append(f"  Køklassifisering: {area['details'].get('classification', 'UNAVAILABLE')}")
    lines.extend(
        [
            "",
            "Sikkerhetsbekreftelse:",
            "- writes_performed=false",
            "- services_changed=false",
            "- database_changed=false",
            "- radio_changed=false",
            "- messages_sent=false",
            "- repair_attempted=false",
        ]
    )
    return "\n".join(lines) + "\n"


def _bounded_samples(value: str) -> int:
    number = int(value)
    if not 2 <= number <= FORENSICS_MAX_SAMPLES:
        raise argparse.ArgumentTypeError(
            f"må være mellom 2 og {FORENSICS_MAX_SAMPLES}"
        )
    return number


def _bounded_interval(value: str) -> int:
    number = int(value)
    if not 0 <= number <= FORENSICS_MAX_INTERVAL_SECONDS:
        raise argparse.ArgumentTypeError(
            f"må være mellom 0 og {FORENSICS_MAX_INTERVAL_SECONDS}"
        )
    return number


def _default_bundle_path() -> Path:
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    downloads = Path.home() / "Downloads"
    parent = downloads if downloads.is_dir() else Path.cwd()
    return parent / f"GuToChat-diagnostics-{stamp}.zip"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gutodiag", description="Lean status and diagnostics for GuToChat")
    parser.add_argument("--version", action="version", version=f"gutodiag {CLI_VERSION} / GuToChat {app_version()}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    status_parser = subparsers.add_parser("status", help="show one combined GuToChat health summary")
    status_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    status_parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    status_parser.add_argument("--strict", action="store_true", help="return exit code 2 for WARNING as well as FAIL")

    collect_parser = subparsers.add_parser("collect", help="create a privacy-reduced diagnostic ZIP")
    collect_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    collect_parser.add_argument("--output", type=Path, default=None)

    forensics_parser = subparsers.add_parser(
        "forensics",
        help="build a read-only evidence report for an unclear operational state",
    )
    forensics_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    forensics_parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    forensics_parser.add_argument("--strict", action="store_true", help="return exit code 2 for UNKNOWN as well as FAIL")
    forensics_parser.add_argument("--candidate-root", type=Path, default=None)
    forensics_parser.add_argument("--backup-root", type=Path, default=None)
    forensics_parser.add_argument("--log-root", type=Path, default=None)
    forensics_parser.add_argument("--samples", type=_bounded_samples, default=2)
    forensics_parser.add_argument("--interval-seconds", type=_bounded_interval, default=1)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        status = build_status(args.config.expanduser())
        if args.json:
            print(json.dumps(status, indent=2, ensure_ascii=False))
        else:
            print(_format_status_text(status), end="")
        if status["overall"] == "FAIL" or (args.strict and status["overall"] == "WARNING"):
            return 2
        if status["overall"] == "WARNING":
            return 1
        return 0

    if args.command == "forensics":
        try:
            report = build_forensics(
                args.config,
                candidate_root=args.candidate_root,
                backup_root=args.backup_root,
                log_root=args.log_root,
                samples=args.samples,
                interval_seconds=args.interval_seconds,
            )
        except Exception as exc:
            print(
                f"Kunne ikke bygge forensicsrapport: {type(exc).__name__}: {_redact_text(exc)}",
                file=sys.stderr,
            )
            return 2
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(_format_forensics_text(report), end="")
        if report["overall"] == "FAIL" or (args.strict and report["overall"] == "UNKNOWN"):
            return 2
        if report["overall"] == "UNKNOWN":
            return 1
        return 0

    if args.command == "collect":
        output = args.output or _default_bundle_path()
        try:
            bundle, sidecar = write_privacy_reduced_bundle(output, args.config.expanduser())
        except Exception as exc:
            print(f"Kunne ikke lage diagnostikkpakke: {type(exc).__name__}: {_redact_text(exc)}", file=sys.stderr)
            return 2
        digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
        print(f"Diagnostikkpakke: {bundle}")
        print(f"SHA256: {digest}")
        print(f"Sidefil: {sidecar}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
