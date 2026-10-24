from __future__ import annotations
from app.map_pub_proxy_contract_v2 import DeviceProxyState, HostProxyGate, eligibility, Eligibility
from app.map_pub_proxy_feed_v2 import ProxyFeedRecord, FeedSequenceGuard

class ProxyController:
    def __init__(self, broker, gate: HostProxyGate):
        self.broker = broker
        self.gate = gate
        self.device = DeviceProxyState(None, None, None, None, None, False)
        self.guard = FeedSequenceGuard()

    def set_device_state(self, device: DeviceProxyState):
        self.device = device
        d = eligibility(self.device, self.gate)
        if d.result is Eligibility.BLOCK and getattr(self.broker, "live", False):
            self.broker.disconnect()
        return d

    def process(self, rec: ProxyFeedRecord):
        self.guard.accept(rec)
        if rec.record_type == "CONNECTION_STATE":
            return "CONNECTION_ANCHOR_ACCEPTED"
        if rec.record_type == "MQTT_CLIENT_PROXY_PUBLISH":
            d = eligibility(self.device, self.gate)
            if d.result is not Eligibility.ALLOW:
                if getattr(self.broker, "live", False):
                    self.broker.disconnect()
                return "BLOCKED:" + d.reason
            topic, payload, retained, qos = rec.publish_tuple()
            if not getattr(self.broker, "live", False):
                self.broker.connect()
            self.broker.publish(topic=topic, payload=payload, retained=retained, qos=qos)
            return "PUBLISHED_PROXY_EXACT_PAYLOAD"
        return "IGNORED"
