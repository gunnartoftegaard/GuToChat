#!/usr/bin/env python3
"""R2-E.A3-A1 GUI-facing live APRS-IS control coordinator.

No action occurs at construction.  ARM is network-free. START runs exactly one
bounded controller session on a worker thread. STOP/OFF only sets the stop flag
(or disarms before a run); no tab/map/presentation action can invoke START.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, Optional

from field_aprs_is_live_control import FieldAprsIsLiveController, LiveRunResult, LiveState


@dataclass(frozen=True)
class GuiLiveSnapshot:
    state: str
    running: bool
    stop_requested: bool


class FieldAprsIsGuiLiveControl:
    def __init__(self, controller: FieldAprsIsLiveController) -> None:
        self.controller = controller
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._completed_result: Optional[LiveRunResult] = None
        self._result_lock = threading.Lock()

    def snapshot(self) -> GuiLiveSnapshot:
        thread = self._thread
        return GuiLiveSnapshot(
            state=self.controller.state.value,
            running=bool(thread and thread.is_alive()),
            stop_requested=self._stop_event.is_set(),
        )

    def arm(self) -> None:
        if self.snapshot().running:
            raise RuntimeError('cannot arm while live session is running')
        self._stop_event.clear()
        with self._result_lock:
            self._completed_result = None
        self.controller.arm()

    def stop_off(self) -> None:
        self._stop_event.set()
        if not self.snapshot().running and self.controller.state is not LiveState.OFF:
            self.controller.disarm()

    def start_bounded_async(
        self,
        *,
        max_packets: int,
        max_seconds: float,
        connector=None,
    ) -> None:
        if self.snapshot().running:
            raise RuntimeError('live APRS-IS session already running')
        if self.controller.state is not LiveState.ARMED:
            raise RuntimeError('explicit operator ARM required before START')
        self._stop_event.clear()

        def worker() -> None:
            result = self.controller.run_once_bounded(
                max_packets=max_packets,
                max_seconds=max_seconds,
                connector=connector,
                stop_requested=self._stop_event.is_set,
            )
            with self._result_lock:
                self._completed_result = result

        self._thread = threading.Thread(target=worker, name='field-aprs-is-live', daemon=True)
        self._thread.start()

    def take_completed_result(self) -> Optional[LiveRunResult]:
        """Return one completed worker result exactly once; performs no GUI/Tk call."""
        with self._result_lock:
            result = self._completed_result
            self._completed_result = None
        return result
