"""Fail-closed host broker-transport interlock for native proxy architecture."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Optional

EXPECTED_NODE = "!0400a3ac"
VALID_READ_SOURCE = "existing_serial_interface_cached_state"
TARGET_ARCHITECTURE = "NATIVE_MESHTASTIC_MQTT_CLIENT_PROXY_UPLINK_ONLY"

class Eligibility(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"

@dataclass(frozen=True)
class DeviceProxyState:
    publisher_node_id: Optional[str]
    identity_match: Optional[bool]
    mqtt_enabled: Optional[bool]
    proxy_to_client_enabled: Optional[bool]
    read_source: Optional[str]
    state_fresh: bool

    def trusted(self) -> bool:
        return (
            self.state_fresh
            and self.identity_match is True
            and (self.publisher_node_id or "").lower() == EXPECTED_NODE.lower()
            and self.read_source == VALID_READ_SOURCE
        )

    def direct_broker_transport_on(self) -> bool:
        return self.trusted() and self.mqtt_enabled is True and self.proxy_to_client_enabled is False

    def proxy_mode_ready(self) -> bool:
        return self.trusted() and self.mqtt_enabled is True and self.proxy_to_client_enabled is True

@dataclass(frozen=True)
class HostProxyGate:
    armed: bool
    configuration_complete: bool
    credentials_verified: bool
    mqtt_contract_verified: bool
    implementation_verified: bool
    feed_healthy: bool
    architecture: str = TARGET_ARCHITECTURE

@dataclass(frozen=True)
class Decision:
    result: Eligibility
    reason: str

def eligibility(device: DeviceProxyState, gate: HostProxyGate) -> Decision:
    if not gate.armed:
        return Decision(Eligibility.BLOCK, "HOST_NOT_ARMED")
    if gate.architecture != TARGET_ARCHITECTURE:
        return Decision(Eligibility.BLOCK, "ARCHITECTURE_MISMATCH")
    if not gate.configuration_complete:
        return Decision(Eligibility.BLOCK, "HOST_CONFIGURATION_INCOMPLETE")
    if not gate.credentials_verified:
        return Decision(Eligibility.BLOCK, "CREDENTIALS_UNVERIFIED")
    if not gate.mqtt_contract_verified:
        return Decision(Eligibility.BLOCK, "MQTT_CONTRACT_UNVERIFIED")
    if not gate.implementation_verified:
        return Decision(Eligibility.BLOCK, "IMPLEMENTATION_UNVERIFIED")
    if not gate.feed_healthy:
        return Decision(Eligibility.BLOCK, "FEED_UNHEALTHY")
    if not device.trusted():
        return Decision(Eligibility.BLOCK, "DEVICE_STATE_UNKNOWN_OR_UNTRUSTED")
    if device.direct_broker_transport_on():
        return Decision(Eligibility.BLOCK, "DEVICE_DIRECT_BROKER_TRANSPORT_ACTIVE")
    if not device.proxy_mode_ready():
        return Decision(Eligibility.BLOCK, "DEVICE_PROXY_MODE_NOT_VERIFIED")
    return Decision(Eligibility.ALLOW, "NATIVE_PROXY_GATES_PASS")
