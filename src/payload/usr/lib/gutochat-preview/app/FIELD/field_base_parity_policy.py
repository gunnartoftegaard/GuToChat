from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

DEFAULT_POLICY_PATH = Path.home() / ".config/lorachat-v2/field-base-parity-v1.json"
ENV_POLICY_PATH = "GUTOCHAT_FIELD_BASE_PARITY_POLICY_FILE"
_ALLOWED_KEYS = {
    "field_base_parity_enabled",
    "aprs_field_sync_enabled",
    "remote_base_control_enabled",
    "remote_base_control_field_addresses",
    "remote_base_control_route",
    "remote_base_status_enabled",
    "remote_base_status_field_addresses",
    "remote_base_status_route",
    "remote_base_status_ttl_seconds",
    "aprs_sync_batch_size",
    "field_aprs_replica_database",
}
_META_KEYS = {"schema", "role"}


def _policy_path() -> Path:
    raw = os.environ.get(ENV_POLICY_PATH, "").strip()
    return Path(raw).expanduser() if raw else DEFAULT_POLICY_PATH


def _secure_regular_file(path: Path) -> None:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RuntimeError("field/base parity policy must be a regular non-symlink file")
    if st.st_uid != os.geteuid():
        raise RuntimeError("field/base parity policy owner mismatch")
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise RuntimeError("field/base parity policy mode must be 0600")


def apply_field_base_parity_policy(config: dict[str, Any]) -> dict[str, Any]:
    """Overlay a small, non-authoritative feature policy onto runtime config.

    The authoritative main config file is never modified. Missing policy is a
    fail-closed no-op. A present policy must be owner-only 0600 and may only
    contain explicitly whitelisted parity/APRS-sync/remote-control keys.
    """
    # Optional adapters use protected registration, never a home policy overlay.
    if isinstance(config.get("optional_adapter"), dict):
        return dict(config)
    path = _policy_path()
    if not path.exists():
        return dict(config)
    _secure_regular_file(path)
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise RuntimeError("field/base parity policy must be a JSON object")
    unknown = set(data) - _ALLOWED_KEYS - _META_KEYS
    if unknown:
        raise RuntimeError("unknown field/base parity policy keys: " + ",".join(sorted(unknown)))
    if data.get("schema", "gutochat.field-base-parity.policy.v1") != "gutochat.field-base-parity.policy.v1":
        raise RuntimeError("unsupported field/base parity policy schema")
    role = str(config.get("role", "")).strip().lower()
    policy_role = str(data.get("role", role)).strip().lower()
    if policy_role and role and policy_role != role:
        raise RuntimeError("field/base parity policy role mismatch")

    merged = dict(config)
    for key in _ALLOWED_KEYS:
        if key in data:
            merged[key] = data[key]

    parity = bool(merged.get("field_base_parity_enabled", False))
    aprs_sync = bool(merged.get("aprs_field_sync_enabled", parity))
    remote = bool(merged.get("remote_base_control_enabled", False))
    allowlist = merged.get("remote_base_control_field_addresses", [])
    status = bool(merged.get("remote_base_status_enabled", False))
    status_allowlist = merged.get("remote_base_status_field_addresses", [])
    if not parity and (aprs_sync or remote or status):
        raise RuntimeError("dependent parity features require field_base_parity_enabled")
    if remote and not isinstance(allowlist, list):
        raise RuntimeError("remote_base_control_field_addresses must be a list")
    if status and not isinstance(status_allowlist, list):
        raise RuntimeError("remote_base_status_field_addresses must be a list")
    return merged
