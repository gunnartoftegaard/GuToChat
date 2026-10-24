"""Generation-aware host broker transport runtime candidate v7r2.

A2-1.7D-R2 adds one startup safety behavior: if and only if the systemd
arm credential is already expired at process start, remain alive permanently
unarmed for that process. All other arm-construction failures remain fatal.
A fresh process is still required after any re-arm.
"""
from __future__ import annotations
import argparse, json, os, select, socket, stat, time
from pathlib import Path
from typing import Callable, Optional
from app.map_pub_arm_v1 import load_arm
from app.map_pub_credentials_v2 import load_credentials
from app.map_pub_mqtt311_publish_only_v2 import PublishOnlyMQTT311
from app.map_pub_proxy_contract_v3 import DeviceProxyState, HostProxyGate
from app.map_pub_proxy_controller_v3 import ProxyController
from app.map_pub_proxy_feed_v3 import ProxyFeedRecord
from app.map_pub_proxy_runtime_v5 import ArmSourceIdentity, ProcessArmInterlock, read_arm_source_identity, replace_gate_armed

MAX_FEED_BUFFER=1024*1024

def resolve_systemd_credential(name:str)->str:
    if not name or "/" in name or name in (".",".."): raise RuntimeError("CREDENTIAL_NAME_INVALID")
    directory=os.environ.get("CREDENTIALS_DIRECTORY","")
    if not directory: raise RuntimeError("SYSTEMD_CREDENTIALS_DIRECTORY_MISSING")
    base=Path(directory).resolve(); path=(base/name).resolve()
    if path.parent!=base or not path.is_file(): raise RuntimeError("SYSTEMD_CREDENTIAL_MISSING:"+name)
    return str(path)

def _control_request(obj,host="127.0.0.1",port=8766,timeout=1.0):
    wire=(json.dumps(obj,separators=(",",":"))+"\n").encode()
    with socket.create_connection((host,port),timeout=timeout) as s:
        s.sendall(wire); line=s.makefile("rb").readline(1024*1024)
    if not line: raise RuntimeError("CONTROL_API_EMPTY_RESPONSE")
    return json.loads(line)

def read_device_proxy_state(expected_node:str,*,host="127.0.0.1",port=8766,timeout=1.0)->DeviceProxyState:
    try:
        st=_control_request({"command":"publication_transport_status","expected_node_id":expected_node},host,port,timeout).get("publication_transport_status") or {}
        return DeviceProxyState(st.get("publisher_node_id"),st.get("identity_match"),st.get("mqtt_enabled"),st.get("proxy_to_client_enabled"),st.get("transport_owner"),st.get("publication_path_configured"),st.get("channel_state_complete"),st.get("control_state"),st.get("feed_generation"),st.get("read_source"),st.get("state_fresh") is True)
    except Exception:
        return DeviceProxyState(None,None,None,None,None,None,None,None,None,None,False)

def process_record_with_observability(controller:ProxyController,rec:ProxyFeedRecord,emit):
    """Process one feed record with payload-free lazy-connect observability.

    No topic or payload bytes are emitted. A real proxy publish is observable as
    ATTEMPT followed by either PUBLISHED_PROXY_EXACT_PAYLOAD or a typed failure.
    """
    is_publish=rec.record_type=="MQTT_CLIENT_PROXY_PUBLISH"
    if is_publish:
        emit("PROXY_PUBLISH_ATTEMPT")
    try:
        result=controller.process(rec)
    except Exception as exc:
        if is_publish:
            emit("PROXY_PUBLISH_FAILED:"+type(exc).__name__)
        raise
    emit(result)
    return result

class StartupExpiredArmInterlock:
    """Permanent fail-closed interlock for a process started with ARM_EXPIRED.

    This process can never become armed. Re-arming requires a new process so
    systemd supplies a fresh credential snapshot and the normal
    ProcessArmInterlock constructor can validate it.
    """
    def __init__(self, *, poll_interval: float = 0.5, monotonic: Callable[[], float] = time.monotonic):
        if poll_interval <= 0:
            raise ValueError("ARM_POLL_INTERVAL_MUST_BE_POSITIVE")
        self.poll_interval = float(poll_interval)
        self._monotonic = monotonic
        self._next_poll = self._monotonic()

    @property
    def revoked_latched(self) -> bool:
        return True

    def poll(self, controller: ProxyController, *, force: bool = False):
        now = self._monotonic()
        if not force and now < self._next_poll:
            return None
        self._next_poll = self._monotonic() + self.poll_interval
        replace_gate_armed(controller, False)
        return False

    def seconds_until_poll(self) -> float:
        return max(0.0, self._next_poll - self._monotonic())


def build_process_arm_interlock(
    arm_credential_path: str,
    arm_source_path: str,
    expected_node: str,
    expected_broker: str,
    expected_root: str,
    *,
    poll_interval: float,
    require_source_secure_metadata: bool = True,
    interlock_cls=ProcessArmInterlock,
    emit=None,
):
    if emit is None:
        emit=lambda result: print(json.dumps({"result":result},separators=(",",":")),flush=True)
    try:
        return interlock_cls(
            arm_credential_path, arm_source_path, expected_node, expected_broker,
            expected_root, poll_interval=poll_interval,
            require_source_secure_metadata=require_source_secure_metadata,
        )
    except ValueError as exc:
        if str(exc) != "ARM_EXPIRED":
            raise
        emit("ARM_START_FAIL_CLOSED:ARM_EXPIRED")
        return StartupExpiredArmInterlock(poll_interval=poll_interval)


class ContinuousStateInterlock:
    def __init__(self,controller:ProxyController,expected_node:str,*,poll_interval:float=0.5,control_host:str="127.0.0.1",control_port:int=8766,control_timeout:float=1.0,read_state:Callable[...,DeviceProxyState]=read_device_proxy_state,monotonic:Callable[[],float]=time.monotonic):
        if poll_interval<=0 or control_timeout<=0: raise ValueError("INVALID_STATE_INTERLOCK_INTERVAL")
        self.controller=controller; self.expected_node=expected_node; self.poll_interval=float(poll_interval); self.control_host=control_host; self.control_port=int(control_port); self.control_timeout=float(control_timeout); self._read_state=read_state; self._monotonic=monotonic; self._next_poll=self._monotonic()
    def poll(self,*,force=False):
        now=self._monotonic()
        if not force and now<self._next_poll:return None
        d=self._read_state(self.expected_node,host=self.control_host,port=self.control_port,timeout=self.control_timeout)
        decision=self.controller.set_device_state(d); self._next_poll=self._monotonic()+self.poll_interval; return decision
    def seconds_until_poll(self): return max(0.0,self._next_poll-self._monotonic())

def run_feed_session(feed_socket,controller,expected_node,process_arm_interlock,*,state_poll_interval=0.5,control_host="127.0.0.1",control_port=8766,control_timeout=1.0,read_state=read_device_proxy_state,emit=None):
    if emit is None: emit=lambda result:print(json.dumps({"result":result},separators=(",",":")),flush=True)
    monitor=ContinuousStateInterlock(controller,expected_node,poll_interval=state_poll_interval,control_host=control_host,control_port=control_port,control_timeout=control_timeout,read_state=read_state)
    buf=bytearray(); process_arm_interlock.poll(controller,force=True); monitor.poll(force=True)
    while True:
        timeout=min(monitor.seconds_until_poll(),process_arm_interlock.seconds_until_poll())
        readable,_,_=select.select([feed_socket],[],[],timeout)
        process_arm_interlock.poll(controller); monitor.poll()
        if not readable: continue
        chunk=feed_socket.recv(65536)
        if not chunk: raise RuntimeError("LOCAL_PROXY_FEED_EOF")
        buf.extend(chunk)
        if len(buf)>MAX_FEED_BUFFER: raise RuntimeError("LOCAL_PROXY_FEED_BUFFER_LIMIT")
        while True:
            nl=buf.find(b"\n")
            if nl<0:break
            raw=bytes(buf[:nl]); del buf[:nl+1]
            if not raw.strip():continue
            rec=ProxyFeedRecord.from_mapping(json.loads(raw.decode()))
            if rec.record_type=="MQTT_CLIENT_PROXY_PUBLISH":
                process_arm_interlock.poll(controller,force=True); monitor.poll(force=True)
            result=process_record_with_observability(controller,rec,emit)
            if rec.record_type=="CONNECTION_STATE": monitor.poll(force=True)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--feed-socket",required=True); ap.add_argument("--credential-name",default="map-pub-host-credentials-v1.json"); ap.add_argument("--arm-name",default="MAP_PUB_PROXY_ARMED"); ap.add_argument("--arm-source-path",default="/etc/gutochat/MAP_PUB_PROXY_ARMED"); ap.add_argument("--broker",default="mqtt.868.no"); ap.add_argument("--port",type=int,default=1883); ap.add_argument("--node",default="!0400a3ac"); ap.add_argument("--production-network-enable",action="store_true"); ap.add_argument("--reconnect-delay",type=float,default=2.0); ap.add_argument("--state-poll-interval",type=float,default=0.5); ap.add_argument("--arm-poll-interval",type=float,default=0.5); ap.add_argument("--control-timeout",type=float,default=1.0); a=ap.parse_args()
    if not a.production_network_enable: raise SystemExit("FAIL_CLOSED_PRODUCTION_NETWORK_NOT_EXPLICITLY_ENABLED")
    credential_path=resolve_systemd_credential(a.credential_name); arm_path=resolve_systemd_credential(a.arm_name)
    cred=load_credentials(credential_path,expected_node=a.node,expected_broker=a.broker,expected_port=a.port,require_secure_metadata=False)
    process_arm=build_process_arm_interlock(arm_path,a.arm_source_path,a.node,a.broker,"msh/EU_868/NO/Østlandet",poll_interval=a.arm_poll_interval,require_source_secure_metadata=True)
    broker=PublishOnlyMQTT311(cred.broker,cred.port,cred.username,cred.password,tls=False); base_gate=HostProxyGate(True,True,True,True,True,True)
    while True:
        ctl=ProxyController(broker,base_gate); s=None
        try:
            s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(a.feed_socket)
            run_feed_session(s,ctl,a.node,process_arm,state_poll_interval=a.state_poll_interval,control_timeout=a.control_timeout)
        except Exception as exc:
            if broker.live: broker.disconnect()
            print(json.dumps({"result":"FEED_FAIL_CLOSED","reason":type(exc).__name__},separators=(",",":")),flush=True); time.sleep(max(a.reconnect_delay,0.2))
        finally:
            if s is not None:
                try:s.close()
                except Exception:pass
if __name__=="__main__": main()
