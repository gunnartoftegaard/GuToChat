#!/usr/bin/env python3
"""Bounded cross-thread handoff for APRS-A2 persistence.

The submitting AF_UNIX thread never owns or opens SQLite.  It places at most
one request in this bridge and waits for the A1H runtime worker to service it.

This module deliberately contains no APRS parser, store or SQLite dependency.
The writer callback is supplied and executed only by the runtime worker.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import queue
import threading
from typing import Any, Callable


WriterHandler = Callable[
    [dict[str, Any], str],
    dict[str, Any],
]


@dataclass
class _BridgeRequest:
    event: dict[str, Any]
    receiver_id: str
    done: threading.Event = field(
        default_factory=threading.Event,
    )
    lock: threading.Lock = field(
        default_factory=threading.Lock,
    )
    started: bool = False
    cancelled: bool = False
    result: dict[str, Any] | None = None


class A2SingleWriterBridge:
    """One-slot A2 handoff into the A1H persistence worker."""

    def __init__(
        self,
        *,
        submit_timeout_seconds: float = 2.0,
    ) -> None:
        timeout = float(submit_timeout_seconds)

        if not 0.05 <= timeout <= 30.0:
            raise ValueError(
                "A2 bridge submit timeout must be within 0.05..30 seconds"
            )

        self.submit_timeout_seconds = timeout
        self._queue: queue.Queue[_BridgeRequest] = queue.Queue(
            maxsize=1
        )

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    def submit(
        self,
        event: dict[str, Any],
        receiver_id: str,
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Submit one request without performing persistence in this thread."""
        if not isinstance(event, dict):
            return {
                "persisted": False,
                "bridge_result": "invalid_event",
            }

        receiver = str(receiver_id).strip()

        if not receiver:
            return {
                "persisted": False,
                "bridge_result": "invalid_receiver",
            }

        timeout = (
            self.submit_timeout_seconds
            if timeout_seconds is None
            else float(timeout_seconds)
        )

        if not 0.01 <= timeout <= 30.0:
            raise ValueError(
                "A2 bridge wait timeout must be within 0.01..30 seconds"
            )

        request = _BridgeRequest(
            event=dict(event),
            receiver_id=receiver,
        )

        try:
            self._queue.put_nowait(request)
        except queue.Full:
            return {
                "persisted": False,
                "bridge_result": "backpressure",
            }

        if request.done.wait(timeout):
            with request.lock:
                result = request.result

            if isinstance(result, dict):
                return dict(result)

            return {
                "persisted": False,
                "bridge_result": "invalid_writer_result",
            }

        with request.lock:
            if not request.started:
                request.cancelled = True

            if request.done.is_set() and isinstance(
                request.result,
                dict,
            ):
                return dict(request.result)

        return {
            "persisted": False,
            "bridge_result": "timeout",
        }

    def service_one(
        self,
        writer: WriterHandler,
    ) -> bool:
        """Service at most one request in the caller's thread."""
        if not callable(writer):
            raise TypeError(
                "A2 bridge writer must be callable"
            )

        try:
            request = self._queue.get_nowait()
        except queue.Empty:
            return False

        try:
            with request.lock:
                if request.cancelled:
                    request.result = {
                        "persisted": False,
                        "bridge_result": "cancelled",
                    }
                    request.done.set()
                    return True

                request.started = True

            try:
                result = writer(
                    request.event,
                    request.receiver_id,
                )
            except BaseException:
                result = {
                    "persisted": False,
                    "bridge_result": "writer_error",
                }

            if not isinstance(result, dict):
                result = {
                    "persisted": False,
                    "bridge_result": "invalid_writer_result",
                }

            with request.lock:
                request.result = dict(result)
                request.done.set()

            return True

        finally:
            self._queue.task_done()

    def cancel_pending(self) -> int:
        """Fail closed and wake any submitters still queued."""
        cancelled = 0

        while True:
            try:
                request = self._queue.get_nowait()
            except queue.Empty:
                break

            try:
                with request.lock:
                    request.cancelled = True
                    request.result = {
                        "persisted": False,
                        "bridge_result": "shutdown",
                    }
                    request.done.set()

                cancelled += 1

            finally:
                self._queue.task_done()

        return cancelled
