#!/usr/bin/env python3
"""R2-E.A3-A0 isolated Field live APRS-IS enablement controller.

Contract:
- starts OFF and performs no network or DB creation at construction
- live session requires one explicit operator arm per run
- receive-only APRS-IS client remains pass -1 + one range filter
- session is bounded and fail-closed: any exception returns controller to OFF
- cache is the separate APRS-IS presentation DB only
- no APRS-IS->RF path or transmit API is exposed here
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from field_aprs_is_presentation import FieldAprsIsPresentationConfig, FieldAprsIsPresentationSource


class LiveState(str, Enum):
    OFF = "OFF"
    ARMED = "ARMED"
    RUNNING = "RUNNING"


@dataclass(frozen=True)
class LiveRunResult:
    success: bool
    state_after: LiveState
    packets_received: int = 0
    positions_parsed: int = 0
    error: str = ""


class FieldAprsIsLiveController:
    """One-shot, operator-armed receive-only APRS-IS session controller."""

    def __init__(self, config: FieldAprsIsPresentationConfig) -> None:
        # Force startup OFF even if a caller passes enabled=True. A live run
        # requires explicit arm() in this process lifetime.
        self._config = FieldAprsIsPresentationConfig(
            login=config.login,
            range_filter=config.range_filter,
            cache_db=config.cache_db,
            enabled=False,
        )
        self._state = LiveState.OFF

    @property
    def state(self) -> LiveState:
        return self._state

    def arm(self) -> None:
        if self._state is not LiveState.OFF:
            raise RuntimeError(f"cannot arm from {self._state.value}")
        self._state = LiveState.ARMED

    def disarm(self) -> None:
        if self._state is LiveState.RUNNING:
            raise RuntimeError("cannot disarm while live session is running")
        self._state = LiveState.OFF

    def run_once_bounded(
        self,
        *,
        max_packets: int = 25,
        max_seconds: float = 30.0,
        connector: Any | None = None,
        stop_requested: Callable[[], bool] | None = None,
    ) -> LiveRunResult:
        if self._state is not LiveState.ARMED:
            raise RuntimeError("explicit operator arm required before live APRS-IS")
        self._state = LiveState.RUNNING
        try:
            enabled = FieldAprsIsPresentationConfig(
                login=self._config.login,
                range_filter=self._config.range_filter,
                cache_db=self._config.cache_db,
                enabled=True,
            )
            src = FieldAprsIsPresentationSource(enabled)
            kwargs = {} if connector is None else {"connector": connector}
            client = src.build_live_client(**kwargs)
            stats = client.run_bounded(
                max_packets=max_packets,
                max_seconds=max_seconds,
                stop_requested=stop_requested,
            )
            return LiveRunResult(
                success=True,
                state_after=LiveState.OFF,
                packets_received=stats.packets_received,
                positions_parsed=stats.positions_parsed,
            )
        except Exception as exc:
            return LiveRunResult(
                success=False,
                state_after=LiveState.OFF,
                error=f"{type(exc).__name__}: {exc}",
            )
        finally:
            # One arm is consumed by one attempted session, regardless of result.
            self._state = LiveState.OFF
