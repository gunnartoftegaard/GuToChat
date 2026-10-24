from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

SERVICE = "aprsis-v2.service"
LOCAL_INGEST_SERVICE = "aprs-a2-ingest-owner-v2.service"


class DirectAprsIsState(str, Enum):
    ON = "ON"
    OFF = "OFF"
    DEGRADED = "DEGRADED"


@dataclass(frozen=True)
class DirectAprsIsPolicy:
    receive_only: bool
    aprs_transmit: bool
    cross_network_routing: bool

    @property
    def safe(self) -> bool:
        return self.receive_only and not self.aprs_transmit and not self.cross_network_routing


@dataclass(frozen=True)
class DirectAprsIsSnapshot:
    active: bool
    enabled: bool
    headless_fresh: bool
    headless_running: bool
    headless_connected: bool
    headless_error: str
    policy: DirectAprsIsPolicy


@dataclass(frozen=True)
class DirectAprsIsView:
    state: DirectAprsIsState
    detail_code: str
    actionable: bool


class UnsafePolicyError(RuntimeError):
    pass


def classify(snapshot: DirectAprsIsSnapshot) -> DirectAprsIsView:
    """Classify Base direct APRS-IS independently of RF receive/iGate uplink."""
    if not snapshot.policy.safe:
        return DirectAprsIsView(DirectAprsIsState.DEGRADED, "unsafe_policy", False)

    if not snapshot.active and not snapshot.enabled:
        # Persistent policy-B OFF: stopped now and remains stopped after reboot.
        return DirectAprsIsView(DirectAprsIsState.OFF, "persistent_off", True)

    if snapshot.active and snapshot.enabled:
        if not snapshot.headless_fresh:
            return DirectAprsIsView(DirectAprsIsState.DEGRADED, "headless_status_stale", True)
        if snapshot.headless_error:
            return DirectAprsIsView(DirectAprsIsState.DEGRADED, "headless_error", True)
        if not snapshot.headless_running:
            return DirectAprsIsView(DirectAprsIsState.DEGRADED, "service_active_headless_not_running", True)
        if not snapshot.headless_connected:
            return DirectAprsIsView(DirectAprsIsState.DEGRADED, "running_not_connected", True)
        return DirectAprsIsView(DirectAprsIsState.ON, "enabled_active_connected", True)

    # Policy B treats enabled/inactive and disabled/active as inconsistent.
    if snapshot.enabled and not snapshot.active:
        return DirectAprsIsView(DirectAprsIsState.DEGRADED, "enabled_but_inactive", True)
    return DirectAprsIsView(DirectAprsIsState.DEGRADED, "active_but_disabled", True)


def desired_commands(turn_on: bool, policy: DirectAprsIsPolicy) -> tuple[tuple[str, ...], ...]:
    """Return fixed, non-shell systemctl argv for policy B.

    ON  => disable local-only owner, then enable/start direct APRS-IS owner.
    OFF => disable direct APRS-IS owner, then enable/start local-only owner.
    """
    if not policy.safe:
        raise UnsafePolicyError("direct APRS-IS control blocked by unsafe APRS policy")
    if turn_on:
        return (
            ("systemctl", "--user-placeholder", "disable", "--now", LOCAL_INGEST_SERVICE),
            ("systemctl", "--user-placeholder", "enable", "--now", SERVICE),
        )
    return (
        ("systemctl", "--user-placeholder", "disable", "--now", SERVICE),
        ("systemctl", "--user-placeholder", "enable", "--now", LOCAL_INGEST_SERVICE),
    )


def normalized_system_commands(turn_on: bool, policy: DirectAprsIsPolicy) -> tuple[tuple[str, ...], ...]:
    """Production-intent command shape for a privileged helper.

    The placeholder is removed here only to keep tests explicit that GUI code must not
    invoke a shell. A later production helper must enforce authorization and fixed service.
    """
    cmds = desired_commands(turn_on, policy)
    return tuple(tuple(part for part in cmd if part != "--user-placeholder") for cmd in cmds)


def acceptance(snapshot: DirectAprsIsSnapshot, target_on: bool) -> bool:
    """Post-action verification required by policy B."""
    view = classify(snapshot)
    return view.state is (DirectAprsIsState.ON if target_on else DirectAprsIsState.OFF)


def snapshot_from_mapping(data: Mapping[str, object]) -> DirectAprsIsSnapshot:
    pol = data.get("policy") or {}
    if not isinstance(pol, Mapping):
        pol = {}
    return DirectAprsIsSnapshot(
        active=bool(data.get("active", False)),
        enabled=bool(data.get("enabled", False)),
        headless_fresh=bool(data.get("headless_fresh", False)),
        headless_running=bool(data.get("headless_running", False)),
        headless_connected=bool(data.get("headless_connected", False)),
        headless_error=str(data.get("headless_error", "") or ""),
        policy=DirectAprsIsPolicy(
            receive_only=bool(pol.get("receive_only", False)),
            aprs_transmit=bool(pol.get("aprs_transmit", False)),
            cross_network_routing=bool(pol.get("cross_network_routing", False)),
        ),
    )
