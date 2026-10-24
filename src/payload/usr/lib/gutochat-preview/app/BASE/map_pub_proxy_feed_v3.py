"""Native MQTT Client Proxy local feed contract v3.

Adds in-stream generation rollover anchors so one AF_UNIX consumer can survive
radio SerialInterface replacement/reboot while invalidating stale attestation.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping, Optional
import base64, json

SCHEMA = "gutochat.map_pub.proxy_feed.v3"
EXPECTED_NODE = "!0400a3ac"
EXPECTED_ROOT = "msh/EU_868/NO/Østlandet"
SECRET_TOKENS = ("password","passwd","username","wifi_psk","psk","token","secret","credential")
ALLOWED_TYPES = {"CONNECTION_STATE", "MQTT_CLIENT_PROXY_PUBLISH"}

class FeedRejected(ValueError):
    pass

def _contains_secret_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for k, v in value.items():
            kl = str(k).lower()
            if any(t in kl for t in SECRET_TOKENS):
                return True
            if _contains_secret_key(v):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_secret_key(v) for v in value)
    return False

def validate_topic(topic: str, root: str = EXPECTED_ROOT, node: str = EXPECTED_NODE) -> None:
    if not topic or "\x00" in topic or "+" in topic or "#" in topic:
        raise FeedRejected("TOPIC_INVALID")
    prefix = root.rstrip("/") + "/"
    if not topic.startswith(prefix):
        raise FeedRejected("TOPIC_OUTSIDE_ROOT")
    if topic == root.rstrip("/") + "/2/map/":
        return
    crypt_prefix = root.rstrip("/") + "/2/e/"
    if not topic.startswith(crypt_prefix):
        raise FeedRejected("TOPIC_CLASS_NOT_ALLOWED")
    rest = topic[len(crypt_prefix):]
    parts = rest.split("/")
    if len(parts) != 2 or not parts[0] or parts[1].lower() != node.lower():
        raise FeedRejected("CRYPT_TOPIC_SHAPE_INVALID")
    if any(c in parts[0] for c in ("/", "+", "#", "\x00")):
        raise FeedRejected("CHANNEL_ID_INVALID")

@dataclass(frozen=True)
class ProxyFeedRecord:
    generation: str
    sequence: int
    record_type: str
    publisher_node_id: str
    payload: Mapping[str, Any]
    schema: str = SCHEMA

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ProxyFeedRecord":
        r = cls(
            str(raw.get("generation", "")),
            int(raw.get("sequence", -1)),
            str(raw.get("record_type", "")),
            str(raw.get("publisher_node_id", "")),
            raw.get("payload") or {},
            str(raw.get("schema", "")),
        )
        r.validate()
        return r

    def to_mapping(self) -> dict:
        self.validate()
        return {
            "schema": self.schema,
            "generation": self.generation,
            "sequence": self.sequence,
            "record_type": self.record_type,
            "publisher_node_id": self.publisher_node_id,
            "payload": dict(self.payload),
        }

    def to_json_line(self) -> bytes:
        return (json.dumps(self.to_mapping(), separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")

    def validate(self) -> None:
        if self.schema != SCHEMA:
            raise FeedRejected("SCHEMA_MISMATCH")
        if not self.generation:
            raise FeedRejected("GENERATION_MISSING")
        if self.sequence < 0:
            raise FeedRejected("SEQUENCE_INVALID")
        if self.record_type not in ALLOWED_TYPES:
            raise FeedRejected("RECORD_TYPE_NOT_ALLOWED")
        if self.publisher_node_id.lower() != EXPECTED_NODE.lower():
            raise FeedRejected("PUBLISHER_ID_INVALID")
        if not isinstance(self.payload, Mapping):
            raise FeedRejected("PAYLOAD_NOT_MAPPING")
        if _contains_secret_key(self.payload):
            raise FeedRejected("SECRET_KEY_PRESENT")
        if self.record_type == "CONNECTION_STATE":
            if self.sequence != 0 or self.payload.get("connected") is not True:
                raise FeedRejected("CONNECTION_ANCHOR_INVALID")
        if self.record_type == "MQTT_CLIENT_PROXY_PUBLISH":
            validate_topic(str(self.payload.get("topic", "")))
            if self.payload.get("retained") is not False:
                raise FeedRejected("RETAIN_TRUE_NOT_ALLOWED")
            if str(self.payload.get("payload_variant", "")) != "data":
                raise FeedRejected("TEXT_PROXY_NOT_ALLOWED")
            encoded = str(self.payload.get("payload_b64", ""))
            try:
                data = base64.b64decode(encoded, validate=True)
            except Exception as exc:
                raise FeedRejected("PAYLOAD_B64_INVALID") from exc
            if not data:
                raise FeedRejected("PAYLOAD_EMPTY")
            if len(data) > 4096:
                raise FeedRejected("PAYLOAD_TOO_LARGE")

    def publish_tuple(self):
        if self.record_type != "MQTT_CLIENT_PROXY_PUBLISH":
            raise FeedRejected("NOT_PROXY_PUBLISH_RECORD")
        return (
            str(self.payload["topic"]),
            base64.b64decode(str(self.payload["payload_b64"]), validate=True),
            False,
            0,
        )

class FeedSequenceGuard:
    """Accept first anchor and subsequent explicit generation rollover anchors."""
    def __init__(self):
        self.generation: Optional[str] = None
        self.last_sequence = -1

    def accept(self, rec: ProxyFeedRecord) -> str:
        rec.validate()
        if self.generation is None:
            if rec.record_type != "CONNECTION_STATE" or rec.sequence != 0:
                raise FeedRejected("INITIAL_GENERATION_NOT_ANCHORED")
            self.generation = rec.generation
            self.last_sequence = 0
            return "INITIAL_GENERATION"
        if rec.generation != self.generation:
            if rec.record_type != "CONNECTION_STATE" or rec.sequence != 0:
                raise FeedRejected("GENERATION_CHANGE_NOT_ANCHORED")
            self.generation = rec.generation
            self.last_sequence = 0
            return "GENERATION_ROLLOVER"
        if rec.sequence <= self.last_sequence:
            raise FeedRejected("DUPLICATE_OR_OLD_SEQUENCE")
        self.last_sequence = rec.sequence
        return "ACCEPTED"
