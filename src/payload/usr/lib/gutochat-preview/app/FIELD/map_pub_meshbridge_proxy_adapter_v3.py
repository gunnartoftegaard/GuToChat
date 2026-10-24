"""Process-owned Meshtastic MQTT client-proxy feed candidate v3.

The AF_UNIX feed server survives SerialInterface replacement. Every new radio
interface allocates a new feed generation BEFORE parent SerialInterface init,
and emits an in-stream generation anchor to an already-connected standby host.
"""
from __future__ import annotations
import base64, json, os, select, socket, stat, struct, threading, uuid
from pathlib import Path
from typing import Callable, Optional
from meshtastic.serial_interface import SerialInterface as _MeshtasticSerialInterface
from app.map_pub_proxy_feed_v3 import ProxyFeedRecord

EXPECTED_NODE="!0400a3ac"
DEFAULT_SOCKET="/run/gutochat/map-pub-proxy-feed.sock"

def proxy_message_to_record(proxy, *, generation:str, sequence:int, publisher_node_id:str)->ProxyFeedRecord:
    which=proxy.WhichOneof("payload_variant")
    if which!="data":
        raise ValueError("ONLY_BINARY_PROXY_DATA_ALLOWED")
    rec=ProxyFeedRecord(generation=generation,sequence=sequence,record_type="MQTT_CLIENT_PROXY_PUBLISH",publisher_node_id=publisher_node_id,payload={"topic":str(proxy.topic),"payload_variant":"data","payload_b64":base64.b64encode(bytes(proxy.data)).decode("ascii"),"retained":bool(proxy.retained)})
    rec.validate()
    return rec

class ProcessProxyFeedServer:
    def __init__(self, socket_path:str=DEFAULT_SOCKET, publisher_node_id:str=EXPECTED_NODE, allowed_consumer_uid:int|None=None):
        self.socket_path=socket_path
        self.publisher_node_id=publisher_node_id
        self.allowed_consumer_uid=os.getuid() if allowed_consumer_uid is None else int(allowed_consumer_uid)
        self._generation=""
        self._sequence=0
        self._listen=None
        self._client=None
        self._client_uid=None
        self._lock=threading.RLock()
        self._stop=threading.Event()
        self._thread=None

    @property
    def generation(self):
        with self._lock: return self._generation
    def _probe_client_locked(self):
        if self._client is None:
            return False
        try:
            readable,_,_=select.select([self._client],[],[],0)
            if not readable:
                return True
            peek=self._client.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            if peek:
                # Feed is strictly server->client. Client input is unexpected
                # and is treated fail-closed by dropping the consumer.
                raise RuntimeError("UNEXPECTED_FEED_CLIENT_INPUT")
            try:self._client.close()
            except Exception:pass
            self._client=None; self._client_uid=None
            return False
        except (BlockingIOError, InterruptedError):
            return True
        except Exception:
            try:self._client.close()
            except Exception:pass
            self._client=None; self._client_uid=None
            return False

    @property
    def consumer_connected(self):
        with self._lock: return self._probe_client_locked()
    @property
    def consumer_uid(self):
        with self._lock:
            if not self._probe_client_locked(): return None
            return self._client_uid

    def _peer_uid(self,c):
        if not hasattr(socket,"SO_PEERCRED"):
            return None
        try:
            raw=c.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i"))
            _pid,uid,_gid=struct.unpack("3i",raw)
            return int(uid)
        except Exception:
            return None

    def _safe_unlink_stale(self,p:Path):
        if not p.exists() and not p.is_symlink(): return
        st=p.lstat()
        if not stat.S_ISSOCK(st.st_mode): raise RuntimeError("FEED_PATH_EXISTS_NOT_SOCKET")
        if st.st_uid!=os.getuid(): raise RuntimeError("FEED_SOCKET_NOT_OWNED_BY_SERVICE_USER")
        p.unlink()

    def start(self):
        if self._listen is not None: return
        p=Path(self.socket_path)
        if not p.parent.is_dir(): raise RuntimeError("FEED_RUNTIME_DIRECTORY_MISSING")
        self._safe_unlink_stale(p)
        srv=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        srv.bind(str(p)); os.chmod(p,0o600); srv.listen(1); srv.settimeout(0.5)
        self._listen=srv
        self._thread=threading.Thread(target=self._accept_loop,name="guto-map-proxy-feed",daemon=True)
        self._thread.start()

    def _anchor_locked(self):
        if not self._generation:
            return False
        return self._send_locked(ProxyFeedRecord(self._generation,0,"CONNECTION_STATE",self.publisher_node_id,{"connected":True}))

    def begin_generation(self)->str:
        with self._lock:
            self._generation=uuid.uuid4().hex
            self._sequence=0
            self._anchor_locked()
            return self._generation

    def next_sequence(self,generation:str)->int:
        with self._lock:
            if generation!=self._generation: raise RuntimeError("FEED_GENERATION_STALE")
            self._sequence+=1
            return self._sequence

    def _send_locked(self,rec):
        if self._client is None: return False
        try:
            self._client.sendall(rec.to_json_line()); return True
        except OSError:
            try: self._client.close()
            except Exception: pass
            self._client=None; self._client_uid=None
            return False

    def _accept_loop(self):
        while not self._stop.is_set():
            try: c,_=self._listen.accept()
            except socket.timeout: continue
            except OSError: break
            uid=self._peer_uid(c)
            if uid is None or uid!=self.allowed_consumer_uid:
                try: c.close()
                except Exception: pass
                continue
            with self._lock:
                if self._client is not None:
                    try: self._client.close()
                    except Exception: pass
                self._client=c; self._client_uid=uid
                self._anchor_locked()

    def emit(self,rec:ProxyFeedRecord)->bool:
        rec.validate()
        with self._lock:
            if rec.generation!=self._generation: raise RuntimeError("FEED_GENERATION_MISMATCH")
            return self._send_locked(rec)

    def close(self):
        self._stop.set()
        with self._lock:
            if self._client is not None:
                try:self._client.close()
                except Exception:pass
                self._client=None; self._client_uid=None
            if self._listen is not None:
                try:self._listen.close()
                except Exception:pass
                self._listen=None
        if self._thread is not None:
            self._thread.join(timeout=2); self._thread=None
        p=Path(self.socket_path)
        try:
            if p.exists() and stat.S_ISSOCK(p.lstat().st_mode) and p.lstat().st_uid==os.getuid(): p.unlink()
        except Exception: pass

def handle_from_radio_proxy_candidate(*,from_radio_bytes:bytes,enabled:bool,sink:Optional[Callable[[ProxyFeedRecord],bool]],generation:str,next_sequence:Callable[[],int],publisher_node_id:str,fallback:Callable[[bytes],object]):
    if not enabled: return fallback(from_radio_bytes)
    from meshtastic.protobuf import mesh_pb2
    fr=mesh_pb2.FromRadio(); fr.ParseFromString(from_radio_bytes)
    if not fr.HasField("mqttClientProxyMessage"): return fallback(from_radio_bytes)
    if sink is None: raise RuntimeError("PROXY_SINK_NOT_BOUND")
    rec=proxy_message_to_record(fr.mqttClientProxyMessage,generation=generation,sequence=next_sequence(),publisher_node_id=publisher_node_id)
    sink(rec); return None

class GuToChatProxySerialInterface(_MeshtasticSerialInterface):
    def __init__(self,*args,proxy_server:ProcessProxyFeedServer,**kwargs):
        if proxy_server is None: raise RuntimeError("PROCESS_PROXY_SERVER_REQUIRED")
        self._guto_proxy_server=proxy_server
        self._guto_proxy_generation=proxy_server.begin_generation()
        self._guto_proxy_enabled=True
        super().__init__(*args,**kwargs)

    def _handleFromRadio(self,fromRadioBytes):
        parent=super(); server=self._guto_proxy_server; generation=self._guto_proxy_generation
        return handle_from_radio_proxy_candidate(from_radio_bytes=fromRadioBytes,enabled=self._guto_proxy_enabled,sink=server.emit,generation=generation,next_sequence=lambda:server.next_sequence(generation),publisher_node_id=EXPECTED_NODE,fallback=parent._handleFromRadio)

    def close(self):
        self._guto_proxy_enabled=False
        return super().close()
