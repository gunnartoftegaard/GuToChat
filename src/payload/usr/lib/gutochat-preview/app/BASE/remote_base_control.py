#!/usr/bin/env python3
"""Fail-closed, whitelisted Field→Base system-control coordinator.

Only two resources exist in A1-P1: MAP_PUB and APRS_IS_UPLINK.  This module
contains no shell/RPC escape hatch.  Authentication and source-address checks
are required by the caller before invoking :meth:`handle_control`.

Request idempotency is stored in a dedicated local database, not in the normal
GuToChat product/message database.  A request is claimed before any control
side effect.  If a process is interrupted after claim, the same request_id is
not executed again; the caller must obtain fresh status and issue a new request.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Callable

RESOURCE_MAP_PUB = "MAP_PUB"
RESOURCE_APRS_IS = "APRS_IS_UPLINK"
ALLOWED_RESOURCES = frozenset({RESOURCE_MAP_PUB, RESOURCE_APRS_IS})
VALID_STATES = frozenset({"ON", "OFF"})


class RemoteControlStore:
    """Durable claim/result store for privileged remote-control request ids."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.database_path, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=5000")
        return con

    def _init_db(self) -> None:
        with self._connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS remote_base_control_requests (
                    request_id TEXT PRIMARY KEY,
                    waveshare_source INTEGER NOT NULL,
                    resource TEXT NOT NULL,
                    expected_state TEXT NOT NULL,
                    target_state TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('PENDING','COMPLETED')),
                    result_json TEXT NOT NULL DEFAULT '',
                    created_epoch INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                    completed_epoch INTEGER
                )
                """
            )

    @staticmethod
    def _same_contract(
        row: sqlite3.Row,
        source: int,
        resource: str,
        expected_state: str,
        target_state: str,
    ) -> bool:
        return (
            int(row["waveshare_source"]) == int(source)
            and str(row["resource"]) == resource
            and str(row["expected_state"]) == expected_state
            and str(row["target_state"]) == target_state
        )

    def claim(
        self,
        request_id: str,
        source: int,
        resource: str,
        expected_state: str,
        target_state: str,
    ) -> tuple[str, dict[str, Any] | None]:
        """Atomically claim one request.

        Returns ``("NEW", None)`` when the caller owns execution,
        ``("DUPLICATE", result)`` for an already completed identical request,
        ``("PENDING", None)`` for an identical request that was already claimed,
        or ``("MISMATCH", None)`` if the same request id is reused with different
        source/resource/state parameters.
        """
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT * FROM remote_base_control_requests WHERE request_id=?",
                (str(request_id),),
            ).fetchone()
            if row is None:
                con.execute(
                    "INSERT INTO remote_base_control_requests"
                    "(request_id,waveshare_source,resource,expected_state,target_state,status) "
                    "VALUES(?,?,?,?,?,'PENDING')",
                    (
                        str(request_id), int(source), resource,
                        expected_state, target_state,
                    ),
                )
                return "NEW", None
            if not self._same_contract(
                row, source, resource, expected_state, target_state
            ):
                return "MISMATCH", None
            if str(row["status"]) != "COMPLETED":
                return "PENDING", None
            try:
                result = json.loads(str(row["result_json"] or ""))
            except json.JSONDecodeError:
                result = None
            if not isinstance(result, dict):
                return "DUPLICATE", {
                    "ok": False,
                    "request_id": str(request_id),
                    "resource": resource,
                    "reason_code": "IDEMPOTENCY_STORE_CORRUPT",
                    "verified": False,
                }
            return "DUPLICATE", result

    def complete(self, request_id: str, result: dict[str, Any]) -> None:
        payload = json.dumps(
            result, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        with self._connect() as con:
            changed = con.execute(
                "UPDATE remote_base_control_requests "
                "SET status='COMPLETED',result_json=?,completed_epoch=strftime('%s','now') "
                "WHERE request_id=? AND status='PENDING'",
                (payload, str(request_id)),
            ).rowcount
            if changed != 1:
                raise RuntimeError("IDEMPOTENCY_COMPLETION_STATE_INVALID")


class RemoteBaseStatus:
    """Read-only, resource-specific Base status provider."""

    def __init__(
        self,
        *,
        map_status: Callable[[], dict[str, Any]],
        aprs_status: Callable[[], dict[str, Any]],
    ) -> None:
        self.map_status = map_status
        self.aprs_status = aprs_status

    @staticmethod
    def _normalize_status(resource: str, raw: dict[str, Any]) -> dict[str, Any]:
        if resource == RESOURCE_MAP_PUB:
            state = str(raw.get("state", "UNKNOWN_DEGRADED")).upper()
            verified = state in VALID_STATES and raw.get("identity_match") is not False
            return {
                "resource": resource,
                "state": state if verified else "UNKNOWN_DEGRADED",
                "verified": bool(verified),
                "reason_code": str(raw.get("reason_code") or ""),
            }
        if resource == RESOURCE_APRS_IS:
            state = str(raw.get("state", "UNKNOWN_DEGRADED")).upper()
            ok = raw.get("ok") is True
            result_code = str(raw.get("result_code") or "")
            verified = ok and state in VALID_STATES and result_code in {
                "STATUS_ON", "STATUS_OFF"
            }
            return {
                "resource": resource,
                "state": state if verified else "UNKNOWN_DEGRADED",
                "verified": bool(verified),
                "reason_code": result_code or str(raw.get("state_reason") or ""),
            }
        return {
            "resource": resource,
            "state": "UNKNOWN_DEGRADED",
            "verified": False,
            "reason_code": "RESOURCE_NOT_ALLOWED",
        }

    def status(self, resource: str) -> dict[str, Any]:
        value = str(resource or "").upper()
        if value not in ALLOWED_RESOURCES:
            return {
                "resource": value,
                "state": "UNKNOWN_DEGRADED",
                "verified": False,
                "reason_code": "RESOURCE_NOT_ALLOWED",
            }
        try:
            raw = self.map_status() if value == RESOURCE_MAP_PUB else self.aprs_status()
            if not isinstance(raw, dict):
                raise ValueError
            return self._normalize_status(value, raw)
        except Exception:
            return {
                "resource": value,
                "state": "UNKNOWN_DEGRADED",
                "verified": False,
                "reason_code": "STATUS_READ_FAILED",
            }



class RemoteBaseControl(RemoteBaseStatus):
    """Resource-specific Base controller with verified readback semantics."""

    def __init__(
        self,
        database_path: Path,
        *,
        map_status: Callable[[], dict[str, Any]],
        map_authorize: Callable[[str], dict[str, Any]],
        map_control: Callable[[str, str], dict[str, Any]],
        aprs_status: Callable[[], dict[str, Any]],
        aprs_activate: Callable[[], dict[str, Any]],
        aprs_deactivate: Callable[[], dict[str, Any]],
    ) -> None:
        super().__init__(map_status=map_status, aprs_status=aprs_status)
        self.store = RemoteControlStore(database_path)
        self.map_authorize = map_authorize
        self.map_control = map_control
        self.aprs_activate = aprs_activate
        self.aprs_deactivate = aprs_deactivate

    def _complete(self, request_id: str, result: dict[str, Any]) -> dict[str, Any]:
        try:
            self.store.complete(request_id, result)
        except Exception:
            # Never turn an idempotency-store failure into a successful remote
            # acknowledgement. The operation may already have occurred, so the
            # only safe answer is unverified/unknown and a fresh status read.
            return {
                "ok": False,
                "request_id": request_id,
                "resource": str(result.get("resource", "")),
                "state": "UNKNOWN_DEGRADED",
                "verified": False,
                "reason_code": "IDEMPOTENCY_COMPLETION_FAILED_STATUS_REQUIRED",
            }
        return result

    def handle_control(
        self,
        *,
        request_id: str,
        source: int,
        resource: str,
        expected_state: str,
        target_state: str,
    ) -> dict[str, Any]:
        req = str(request_id or "").strip()
        resource = str(resource or "").strip().upper()
        expected = str(expected_state or "").strip().upper()
        target = str(target_state or "").strip().upper()
        if not req or len(req) > 64:
            return {
                "ok": False,
                "request_id": req,
                "resource": resource,
                "reason_code": "REQUEST_ID_INVALID",
                "verified": False,
            }
        if resource not in ALLOWED_RESOURCES:
            return {
                "ok": False,
                "request_id": req,
                "resource": resource,
                "reason_code": "RESOURCE_NOT_ALLOWED",
                "verified": False,
            }
        if expected not in VALID_STATES or target not in VALID_STATES or expected == target:
            return {
                "ok": False,
                "request_id": req,
                "resource": resource,
                "reason_code": "STATE_TRANSITION_INVALID",
                "verified": False,
            }


        claim_state, previous = self.store.claim(
            req, source, resource, expected, target
        )
        if claim_state == "MISMATCH":
            return {
                "ok": False,
                "request_id": req,
                "resource": resource,
                "reason_code": "REQUEST_ID_CONTRACT_MISMATCH",
                "verified": False,
            }
        if claim_state == "PENDING":
            return {
                "ok": False,
                "request_id": req,
                "resource": resource,
                "reason_code": "REQUEST_ALREADY_CLAIMED_STATUS_REQUIRED",
                "verified": False,
            }
        if claim_state == "DUPLICATE":
            assert previous is not None
            return {**previous, "duplicate": True}

        before = self.status(resource)
        if before.get("verified") is not True:
            return self._complete(
                req,
                {
                    "ok": False,
                    "request_id": req,
                    "resource": resource,
                    "source_state": before.get("state"),
                    "target_state": target,
                    "reason_code": "SOURCE_STATE_UNVERIFIED",
                    "verified": False,
                },
            )
        if before.get("state") != expected:
            return self._complete(
                req,
                {
                    "ok": False,
                    "request_id": req,
                    "resource": resource,
                    "source_state": before.get("state"),
                    "target_state": target,
                    "reason_code": "EXPECTED_STATE_MISMATCH",
                    "verified": False,
                },
            )

        operation: dict[str, Any]
        try:
            if resource == RESOURCE_MAP_PUB:
                auth = self.map_authorize(target)
                token = str(
                    auth.get("authorization_token") or auth.get("token") or ""
                )
                if auth.get("authorized") is not True or not token:
                    operation = {
                        "result_code": str(
                            auth.get("reason_code") or "AUTHORIZATION_FAILED"
                        )
                    }
                else:
                    operation = self.map_control(target, token)
            elif target == "ON":
                operation = self.aprs_activate()
            else:
                operation = self.aprs_deactivate()
        except Exception:
            operation = {"result_code": "CONTROL_EXECUTION_FAILED"}

        after = self.status(resource)
        verified = after.get("verified") is True and after.get("state") == target
        result = {
            "ok": bool(verified),
            "request_id": req,
            "resource": resource,
            "source_state": expected,
            "target_state": target,
            "state": after.get("state", "UNKNOWN_DEGRADED"),
            "verified": bool(verified),
            "reason_code": "TARGET_VERIFIED"
            if verified
            else str(
                operation.get("result_code")
                or after.get("reason_code")
                or "TARGET_NOT_VERIFIED"
            ),
        }
        return self._complete(req, result)
