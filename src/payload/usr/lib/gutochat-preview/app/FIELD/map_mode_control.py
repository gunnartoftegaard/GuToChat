"""R2-D.6 pure operator-mode policy.

This module is deliberately free of Tk, network, database and filesystem writes.
It defines the fail-safe OFFLINE/ONLINE control contract used by the isolated
R2-D.6 candidate.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class MapOperatorMode(str, Enum):
    OFFLINE = "offline"
    ONLINE = "online"


def initial_map_operator_mode() -> MapOperatorMode:
    """Always start fail-safe OFFLINE; no persisted ONLINE auto-resume."""
    return MapOperatorMode.OFFLINE


def network_fetch_allowed(mode: MapOperatorMode, *, explicit_load_request: bool) -> bool:
    """Network tile fetching requires ONLINE mode and an explicit load action."""
    return mode is MapOperatorMode.ONLINE and bool(explicit_load_request)


def mode_after_online_failure() -> MapOperatorMode:
    """Any online rendering/fetch failure falls back to OFFLINE."""
    return MapOperatorMode.OFFLINE


@dataclass(frozen=True)
class MapModePresentation:
    """Pure GUI presentation derived from the authoritative operator mode."""

    status_key: str
    action_key: str
    target_mode: MapOperatorMode


def presentation_for_mode(mode: MapOperatorMode) -> MapModePresentation:
    """Return one shared status/action presentation for both map tabs."""
    if mode is MapOperatorMode.ONLINE:
        return MapModePresentation(
            status_key="map_mode.status.online",
            action_key="map_mode.go_offline",
            target_mode=MapOperatorMode.OFFLINE,
        )
    return MapModePresentation(
        status_key="map_mode.status.offline",
        action_key="map_mode.go_online",
        target_mode=MapOperatorMode.ONLINE,
    )
