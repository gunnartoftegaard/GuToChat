#!/usr/bin/env python3
"""In-memory, target-bound one-shot authorization broker for MAP-PUB control.

The broker deliberately stores only a SHA-256 digest of the bearer token.
Authorization is short-lived, bound to one B868 node, one source state and one
opposite target state, and is removed before a matching token is returned as
consumed.  It does not perform the radio write; meshbridge remains responsible
for all identity/config/readback checks.
"""
from __future__ import annotations

import hashlib
import secrets
import threading
import time
import uuid
from typing import Any

from protocol import canonical_meshtastic_id

AUTH_SCHEMA = "gutochat.map.publication.control_authorization.v3"
DEFAULT_TTL_SECONDS = 30.0
MAX_TTL_SECONDS = 60.0


def _token_digest(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


class AuthorizationBroker:
    """Single-pending, in-memory capability broker.

    A new issue invalidates any previous pending authorization.  A matching
    bearer token is removed before target/expiry checks are returned, so a
    presented capability cannot be replayed after any matching consume attempt.
    """

    def __init__(self, *, ttl_seconds: float = DEFAULT_TTL_SECONDS) -> None:
        ttl = float(ttl_seconds)
        if ttl <= 0.0 or ttl > MAX_TTL_SECONDS:
            raise ValueError("invalid authorization TTL")
        self.ttl_seconds = ttl
        self._lock = threading.Lock()
        self._pending: dict[str, Any] | None = None

    def issue(
        self,
        *,
        expected_node_id: str,
        source_state: str,
        target_state: str,
        now_monotonic: float | None = None,
    ) -> dict[str, Any]:
        expected = canonical_meshtastic_id(str(expected_node_id or "").strip())
        source = str(source_state or "").strip().upper()
        target = str(target_state or "").strip().upper()
        if not expected:
            return {"authorized": False, "reason_code": "AUTH_INVALID_NODE"}
        if source not in {"ON", "OFF"} or target not in {"ON", "OFF"}:
            return {"authorized": False, "reason_code": "AUTH_INVALID_STATE"}
        if source == target:
            return {"authorized": False, "reason_code": "AUTH_TARGET_NOT_OPPOSITE"}

        token = secrets.token_urlsafe(32)
        operation_id = str(uuid.uuid4())
        now = time.monotonic() if now_monotonic is None else float(now_monotonic)
        pending = {
            "schema": AUTH_SCHEMA,
            "operation_id": operation_id,
            "expected_node_id": expected,
            "source_state": source,
            "target_state": target,
            "token_sha256": _token_digest(token),
            "expires_monotonic": now + self.ttl_seconds,
        }
        with self._lock:
            self._pending = pending
        return {
            "authorized": True,
            "reason_code": "AUTHORIZATION_ISSUED_ONE_SHOT",
            "operation_id": operation_id,
            "expected_node_id": expected,
            "source_state": source,
            "target_state": target,
            "authorization_token": token,
            "expires_in_seconds": self.ttl_seconds,
        }

    def consume(
        self,
        authorization_token: str | None,
        *,
        expected_node_id: str,
        target_state: str,
        now_monotonic: float | None = None,
    ) -> dict[str, Any]:
        token = str(authorization_token or "")
        if not token:
            return {"authorized": False, "reason_code": "AUTHORIZATION_REQUIRED"}
        expected = canonical_meshtastic_id(str(expected_node_id or "").strip())
        target = str(target_state or "").strip().upper()
        if not expected or target not in {"ON", "OFF"}:
            return {"authorized": False, "reason_code": "AUTHORIZATION_REQUEST_INVALID"}

        digest = _token_digest(token)
        with self._lock:
            pending = self._pending
            if pending is None:
                return {"authorized": False, "reason_code": "AUTHORIZATION_NOT_PENDING"}
            if not secrets.compare_digest(str(pending.get("token_sha256", "")), digest):
                return {"authorized": False, "reason_code": "AUTHORIZATION_TOKEN_INVALID"}
            # A matching bearer capability becomes unusable immediately,
            # including on expiry/target mismatch.  This is intentional.
            self._pending = None

        now = time.monotonic() if now_monotonic is None else float(now_monotonic)
        if now > float(pending.get("expires_monotonic", -1.0)):
            return {"authorized": False, "reason_code": "AUTHORIZATION_EXPIRED"}
        if str(pending.get("expected_node_id", "")) != expected:
            return {"authorized": False, "reason_code": "AUTHORIZATION_NODE_MISMATCH"}
        if str(pending.get("target_state", "")) != target:
            return {"authorized": False, "reason_code": "AUTHORIZATION_TARGET_MISMATCH"}
        return {
            "authorized": True,
            "reason_code": "AUTHORIZATION_CONSUMED_ONE_SHOT",
            "operation_id": str(pending["operation_id"]),
            "expected_node_id": expected,
            "source_state": str(pending["source_state"]),
            "target_state": target,
        }
