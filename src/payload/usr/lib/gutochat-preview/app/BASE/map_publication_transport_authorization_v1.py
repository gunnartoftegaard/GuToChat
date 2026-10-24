"""Generation-bound one-shot authorization broker for MQTT transport ownership."""
from __future__ import annotations
import hashlib, secrets, threading, time, uuid
from typing import Any
try:
    from .protocol import canonical_meshtastic_id
except ImportError:
    from protocol import canonical_meshtastic_id

AUTH_SCHEMA="gutochat.map.publication.transport_authorization.v1"
DEFAULT_TTL_SECONDS=30.0
MAX_TTL_SECONDS=60.0
VALID_STATES={"DEVICE_DIRECT","HOST_PROXY"}

def _digest(token:str)->str:
    return hashlib.sha256(str(token).encode()).hexdigest()

class TransportAuthorizationBroker:
    def __init__(self, *, ttl_seconds:float=DEFAULT_TTL_SECONDS):
        ttl=float(ttl_seconds)
        if ttl<=0 or ttl>MAX_TTL_SECONDS:
            raise ValueError("invalid authorization TTL")
        self.ttl_seconds=ttl
        self._lock=threading.Lock()
        self._pending:dict[str,Any]|None=None

    def issue(self, *, expected_node_id:str, source_transport:str, target_transport:str, feed_generation:str, now_monotonic:float|None=None):
        expected=canonical_meshtastic_id(str(expected_node_id or "").strip())
        source=str(source_transport or "").strip().upper()
        target=str(target_transport or "").strip().upper()
        generation=str(feed_generation or "").strip()
        if not expected or source not in VALID_STATES or target not in VALID_STATES or source==target or not generation:
            return {"authorized":False,"reason_code":"AUTH_REQUEST_INVALID"}
        token=secrets.token_urlsafe(32)
        op=str(uuid.uuid4())
        now=time.monotonic() if now_monotonic is None else float(now_monotonic)
        pending={"schema":AUTH_SCHEMA,"operation_id":op,"expected_node_id":expected,"source_transport":source,"target_transport":target,"feed_generation":generation,"token_sha256":_digest(token),"expires_monotonic":now+self.ttl_seconds}
        with self._lock:
            self._pending=pending
        return {"authorized":True,"reason_code":"AUTHORIZATION_ISSUED_ONE_SHOT","operation_id":op,"expected_node_id":expected,"source_transport":source,"target_transport":target,"feed_generation":generation,"authorization_token":token,"expires_in_seconds":self.ttl_seconds}

    def consume(self, token:str|None, *, expected_node_id:str, target_transport:str, feed_generation:str, now_monotonic:float|None=None):
        raw=str(token or "")
        if not raw:
            return {"authorized":False,"reason_code":"AUTHORIZATION_REQUIRED"}
        expected=canonical_meshtastic_id(str(expected_node_id or "").strip())
        target=str(target_transport or "").strip().upper()
        generation=str(feed_generation or "").strip()
        digest=_digest(raw)
        with self._lock:
            pending=self._pending
            if pending is None:
                return {"authorized":False,"reason_code":"AUTHORIZATION_NOT_PENDING"}
            if not secrets.compare_digest(str(pending.get("token_sha256","")),digest):
                return {"authorized":False,"reason_code":"AUTHORIZATION_TOKEN_INVALID"}
            self._pending=None
        now=time.monotonic() if now_monotonic is None else float(now_monotonic)
        checks=[
            (now<=float(pending.get("expires_monotonic",-1)),"AUTHORIZATION_EXPIRED"),
            (pending.get("expected_node_id")==expected,"AUTHORIZATION_NODE_MISMATCH"),
            (pending.get("target_transport")==target,"AUTHORIZATION_TARGET_MISMATCH"),
            (pending.get("feed_generation")==generation,"AUTHORIZATION_GENERATION_MISMATCH"),
        ]
        for ok,reason in checks:
            if not ok:
                return {"authorized":False,"reason_code":reason}
        return {"authorized":True,"reason_code":"AUTHORIZATION_CONSUMED_ONE_SHOT","operation_id":pending["operation_id"],"expected_node_id":expected,"source_transport":pending["source_transport"],"target_transport":target,"feed_generation":generation}
