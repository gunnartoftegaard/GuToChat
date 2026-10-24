"""Passive per-interface reception evidence. No probes, payload storage or timers."""
from __future__ import annotations
import threading
import time
import uuid
from datetime import datetime, timezone

FRESH_SECONDS = 300.0

class ReceiveEvidence:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.generation = uuid.uuid4().hex
        self.lock = threading.Lock()
        self.count = 0
        self.last_monotonic = None
        self.last_utc = None

    def record(self):
        with self.lock:
            self.count += 1
            self.last_monotonic = self.clock()
            self.last_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def snapshot(self):
        with self.lock:
            age = None if self.last_monotonic is None else max(0.0, self.clock() - self.last_monotonic)
            return {"generation": self.generation, "frame_count": self.count,
                    "last_frame_utc": self.last_utc, "last_frame_age_seconds": age}

def observed_interface_class(parent):
    """Wrap the existing owner; preserve its normal/proxy processing exactly once."""
    class ObservedInterface(parent):
        def __init__(self, *args, **kwargs):
            self.receive_evidence = ReceiveEvidence()
            # SDK callbacks can arrive during its constructor, before it returns.
            bind = kwargs.pop('_guto_bind_interface', None)
            if bind is not None:
                bind(self)
            super().__init__(*args, **kwargs)

        def _handleFromRadio(self, data):
            # SDK/proxy validates the frame. Failed handlers do not attest success.
            result = super()._handleFromRadio(data)
            if data:
                self.receive_evidence.record()
            return result
    return ObservedInterface

def transport_facts(interface):
    if interface is None:
        return {"reader_alive": None, "sdk_connected": None, "stream_open": None,
                "failure_reason": "INTERFACE_UNAVAILABLE"}
    thread = getattr(interface, "_rxThread", None)
    event = getattr(interface, "isConnected", None)
    stream = getattr(interface, "stream", ...)
    reader = thread.is_alive() if thread is not None else None
    connected = event.is_set() if event is not None else None
    opened = None if stream is ... else bool(stream is not None and getattr(stream, "is_open", True))
    reason = None
    if reader is False:
        reason = "READER_STOPPED"
    elif opened is False:
        reason = "STREAM_CLOSED"
    elif connected is False:
        reason = "SDK_DISCONNECTED"
    return {"reader_alive": reader, "sdk_connected": connected, "stream_open": opened,
            "failure_reason": reason}

def transport_failure(interface):
    return transport_facts(interface)["failure_reason"]

def receive_health_snapshot(interface, online):
    facts = transport_facts(interface)
    evidence = getattr(interface, "receive_evidence", None)
    result = evidence.snapshot() if evidence is not None else {
        "generation": None, "frame_count": 0, "last_frame_utc": None, "last_frame_age_seconds": None}
    result.update(facts)
    age = result["last_frame_age_seconds"]
    if not online or facts["failure_reason"]:
        state = "DISCONNECTED"
    elif evidence is None or any(facts[k] is None for k in ("reader_alive", "sdk_connected", "stream_open")):
        state = "UNKNOWN"
    elif age is None:
        state = "NO_OBSERVATION"
    elif age <= FRESH_SECONDS:
        state = "RECENT_RECEPTION"
    else:
        state = "NO_RECENT_DATA"
    result.update(schema="gutochat.mesh.receive_health.v1", state=state,
                  fresh_window_seconds=FRESH_SECONDS, passive_only=True)
    return result

def receive_health_presentation(status, translate):
    health = status.get("receive_health") or {}
    if not status.get("online") or health.get("state") == "DISCONNECTED":
        return translate("system.state.error"), translate("mesh.receive.disconnected")
    if health.get("state") == "RECENT_RECEPTION":
        age = health.get("last_frame_age_seconds")
        if isinstance(age, (int, float)) and age >= 0:
            return "OK", translate("mesh.receive.recent", seconds=int(age))
    if health.get("state") == "NO_RECENT_DATA":
        age = health.get("last_frame_age_seconds")
        if isinstance(age, (int, float)) and age >= 0:
            return translate("mesh.receive.connected"), translate("mesh.receive.quiet", seconds=int(age))
    return translate("mesh.receive.connected"), translate("mesh.receive.unverified")
