"""Controlled MQTT transport-ownership manager for MAP-PUB A2-1.7S.

Offline candidate only. Reuses the bridge's existing SerialInterface, send lock,
trust anchor and mutation lock. Mutates only mqtt.proxy_to_client_enabled.
"""
from __future__ import annotations
import copy, os, stat, time
from pathlib import Path
from typing import Any
try:
    from .protocol import canonical_meshtastic_id
except ImportError:
    from protocol import canonical_meshtastic_id
try:
    from .map_publication_transport_authorization_v1 import TransportAuthorizationBroker
except ImportError:
    from map_publication_transport_authorization_v1 import TransportAuthorizationBroker

VALID_TARGETS={"DEVICE_DIRECT","HOST_PROXY"}
ARM_SOURCE_DEFAULT="/etc/gutochat/MAP_PUB_PROXY_ARMED"
READ_SOURCE="current_serial_interface_generation_attested_state"

class PublicationTransportManager:
    def __init__(self, bridge:Any, feed_server:Any, *, arm_source_path:str=ARM_SOURCE_DEFAULT, require_arm_source_secure_metadata:bool=True):
        self.bridge=bridge
        self.feed_server=feed_server
        self.arm_source_path=Path(arm_source_path)
        self.require_arm_source_secure_metadata=bool(require_arm_source_secure_metadata)
        self.authorization_broker=TransportAuthorizationBroker()
        self.in_progress=False
        self.unverified=False

    def control_state(self)->str:
        if self.in_progress or bool(getattr(self.bridge,"_publication_control_in_progress",False)):
            return "IN_PROGRESS"
        if self.unverified or bool(getattr(self.bridge,"_publication_control_unverified",False)):
            return "UNVERIFIED"
        return "VERIFIED"

    def _arm_secure_present(self)->bool:
        try:
            st=self.arm_source_path.stat()
            if not self.require_arm_source_secure_metadata:
                return stat.S_ISREG(st.st_mode)
            return st.st_uid==0 and st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600
        except Exception:
            return False

    def _arm_absent(self)->bool:
        try:
            self.arm_source_path.stat(); return False
        except FileNotFoundError:
            return True
        except Exception:
            return False

    @staticmethod
    def _mqtt_non_target_equal(before:Any, after:Any)->bool:
        try:
            a=copy.deepcopy(before); b=copy.deepcopy(after)
            setattr(a,"proxy_to_client_enabled",False)
            setattr(b,"proxy_to_client_enabled",False)
            return bool(a==b)
        except Exception:
            return False

    def _captured_status(self, expected_node_id:str|None=None)->dict[str,Any]:
        bridge=self.bridge
        interface=getattr(bridge,"interface",None)
        generation=getattr(interface,"_guto_proxy_generation",None) if interface is not None else None
        server_generation=getattr(self.feed_server,"generation",None)
        publisher=canonical_meshtastic_id(getattr(bridge,"local_id",None) or None,node_num=getattr(bridge,"local_num",None) or None)
        expected=canonical_meshtastic_id(expected_node_id) if expected_node_id not in (None,"") else None
        result={
            "schema":"gutochat.map.publication.transport_status.v1",
            "publisher_node_id":publisher or None,
            "expected_node_id":expected,
            "identity_match":publisher==expected if expected and publisher else None,
            "bridge_online":bool(getattr(bridge,"online",False)),
            "mqtt_enabled":None,
            "proxy_to_client_enabled":None,
            "transport_owner":"UNKNOWN",
            "publication_path_configured":None,
            "channel_state_complete":False,
            "control_state":self.control_state(),
            "feed_generation":generation,
            "mqtt_config_observed_on_generation":None,
            "feed_consumer_connected":bool(getattr(self.feed_server,"consumer_connected",False)),
            "feed_consumer_uid":getattr(self.feed_server,"consumer_uid",None),
            "state_fresh":False,
            "reason_code":"STATE_NOT_READ",
            "read_source":READ_SOURCE,
        }
        if self.control_state()!="VERIFIED": result["reason_code"]="CONTROL_STATE_UNVERIFIED"; return result
        if interface is None or not result["bridge_online"]: result["reason_code"]="BRIDGE_OFFLINE"; return result
        if not generation or generation!=server_generation: result["reason_code"]="FEED_GENERATION_MISMATCH"; return result
        if not publisher: result["reason_code"]="PUBLISHER_ID_UNAVAILABLE"; return result
        if expected and publisher!=expected: result["reason_code"]="IDENTITY_MISMATCH"; return result
        local_node=getattr(interface,"localNode",None); module_config=getattr(local_node,"moduleConfig",None)
        has_field=getattr(module_config,"HasField",None)
        try: loaded=bool(callable(has_field) and has_field("mqtt"))
        except Exception: loaded=False
        mqtt=getattr(module_config,"mqtt",None) if loaded else None
        if mqtt is None: result["reason_code"]="MQTT_CONFIG_NOT_LOADED"; return result
        # Existing publication_status is still the source for channel/path semantics.
        pub_status=bridge.publication_status(expected)
        # Recheck exact interface/generation after deriving all state.
        if getattr(bridge,"interface",None) is not interface or getattr(interface,"_guto_proxy_generation",None)!=generation or getattr(self.feed_server,"generation",None)!=generation:
            result["reason_code"]="INTERFACE_GENERATION_CHANGED_DURING_STATUS"; return result
        enabled=bool(getattr(mqtt,"enabled",False)); proxy=bool(getattr(mqtt,"proxy_to_client_enabled",False))
        owner="HOST_PROXY" if enabled and proxy else ("DEVICE_DIRECT" if enabled and not proxy else "NONE")
        result.update({
            "mqtt_enabled":enabled,
            "proxy_to_client_enabled":proxy,
            "transport_owner":owner,
            "publication_path_configured":pub_status.get("publication_path_configured"),
            "channel_state_complete":bool(pub_status.get("channel_state_complete")),
            "mqtt_config_observed_on_generation":generation,
            "state_fresh":True,
            "reason_code":"TRANSPORT_STATE_VERIFIED",
        })
        return result

    def status(self, expected_node_id:str|None=None)->dict[str,Any]:
        return self._captured_status(expected_node_id)

    def authorization(self,target_transport:str,expected_node_id:str|None)->dict[str,Any]:
        target=str(target_transport or "").strip().upper()
        if target not in VALID_TARGETS: return {"authorized":False,"reason_code":"BLOCKED_INVALID_TARGET"}
        lock=getattr(self.bridge,"publication_control_lock",None)
        if lock is None or not lock.acquire(blocking=False): return {"authorized":False,"reason_code":"CONTROL_BUSY"}
        try:
            expected,error=self.bridge._publication_control_expected_node_id()
            if error or expected is None: return {"authorized":False,"reason_code":error or "BLOCKED_BINDING_INVALID"}
            requested=canonical_meshtastic_id(str(expected_node_id or "").strip())
            if requested!=expected: return {"authorized":False,"reason_code":"BLOCKED_IDENTITY_MISMATCH"}
            if self.control_state()!="VERIFIED": return {"authorized":False,"reason_code":"BLOCKED_PREVIOUS_CONTROL_UNVERIFIED"}
            st=self.status(expected)
            if st.get("state_fresh") is not True: return {"authorized":False,"reason_code":"BLOCKED_TRANSPORT_STATUS_NOT_FRESH"}
            source=str(st.get("transport_owner","UNKNOWN"))
            required="HOST_PROXY" if source=="DEVICE_DIRECT" else ("DEVICE_DIRECT" if source=="HOST_PROXY" else "")
            if target!=required: return {"authorized":False,"reason_code":"BLOCKED_TARGET_NOT_OPPOSITE_CURRENT_TRANSPORT"}
            if st.get("mqtt_enabled") is not True: return {"authorized":False,"reason_code":"BLOCKED_MQTT_DISABLED"}
            if target=="HOST_PROXY":
                if st.get("publication_path_configured") is not True: return {"authorized":False,"reason_code":"BLOCKED_NO_PUBLICATION_PATH"}
                if not self._arm_secure_present(): return {"authorized":False,"reason_code":"BLOCKED_SECURE_ARM_SOURCE_REQUIRED"}
                if st.get("feed_consumer_connected") is not True: return {"authorized":False,"reason_code":"BLOCKED_STANDBY_CONSUMER_REQUIRED"}
                if int(st.get("feed_consumer_uid",-1))!=os.getuid(): return {"authorized":False,"reason_code":"BLOCKED_STANDBY_CONSUMER_UID"}
            else:
                if not self._arm_absent(): return {"authorized":False,"reason_code":"BLOCKED_ARM_MUST_BE_ABSENT"}
                if st.get("feed_consumer_connected") is True: return {"authorized":False,"reason_code":"BLOCKED_CONSUMER_MUST_BE_DISCONNECTED"}
            return self.authorization_broker.issue(expected_node_id=expected,source_transport=source,target_transport=target,feed_generation=str(st["feed_generation"]))
        except Exception:
            return {"authorized":False,"reason_code":"AUTHORIZATION_INTERNAL_ERROR"}
        finally:
            lock.release()

    def _result(self,code:str,*,target_transport:str|None=None,publisher_node_id:str|None=None,write_sent:bool=False,verified:bool=False,feed_generation:str|None=None):
        return {"result_code":code,"target_transport":target_transport,"publisher_node_id":publisher_node_id,"write_sent":bool(write_sent),"verified":bool(verified),"reboot_expected":bool(write_sent),"feed_generation":feed_generation}

    def control(self,target_transport:str,*,authorization_token:str|None=None,reconnect_timeout_seconds:float=75.0,poll_interval_seconds:float=0.10):
        target=str(target_transport or "").strip().upper()
        if target not in VALID_TARGETS: return self._result("BLOCKED_INVALID_TARGET",target_transport=target or None)
        desired_proxy=target=="HOST_PROXY"
        lock=getattr(self.bridge,"publication_control_lock",None)
        if lock is None: return self._result("BLOCKED_CONTROL_LOCK_UNAVAILABLE",target_transport=target)
        if not lock.acquire(blocking=False): return self._result("CONTROL_BUSY",target_transport=target)
        snapshot=None; write_sent=False; publisher=None
        try:
            expected,error=self.bridge._publication_control_expected_node_id()
            if error or expected is None: return self._result(error or "BLOCKED_BINDING_INVALID",target_transport=target,publisher_node_id=expected)
            if self.unverified or bool(getattr(self.bridge,"_publication_control_unverified",False)):
                return self._result("BLOCKED_PREVIOUS_CONTROL_UNVERIFIED",target_transport=target)
            st=self.status(expected)
            if st.get("state_fresh") is not True: return self._result("BLOCKED_TRANSPORT_STATUS_NOT_FRESH",target_transport=target)
            auth=self.authorization_broker.consume(authorization_token,expected_node_id=expected,target_transport=target,feed_generation=str(st.get("feed_generation") or ""))
            if auth.get("authorized") is not True: return self._result("BLOCKED_"+str(auth.get("reason_code") or "AUTHORIZATION_INVALID"),target_transport=target)
            if auth.get("source_transport")!=st.get("transport_owner"): return self._result("BLOCKED_AUTHORIZATION_SOURCE_CHANGED",target_transport=target)
            # Recheck target-specific cutover/rollback interlocks at consume time.
            if target=="HOST_PROXY":
                if not self._arm_secure_present() or not self.feed_server.consumer_connected or self.feed_server.consumer_uid!=os.getuid():
                    return self._result("BLOCKED_STANDBY_PRECONDITION_CHANGED",target_transport=target)
            else:
                if not self._arm_absent() or self.feed_server.consumer_connected:
                    return self._result("BLOCKED_ROLLBACK_PRECONDITION_CHANGED",target_transport=target)
            bridge=self.bridge; original_interface=getattr(bridge,"interface",None)
            original_generation=getattr(original_interface,"_guto_proxy_generation",None) if original_interface is not None else None
            if original_interface is None or not original_generation: return self._result("BLOCKED_BRIDGE_OFFLINE",target_transport=target)
            publisher=canonical_meshtastic_id(getattr(bridge,"local_id",None) or None,node_num=getattr(bridge,"local_num",None) or None)
            if publisher!=expected: return self._result("BLOCKED_IDENTITY_MISMATCH",target_transport=target,publisher_node_id=publisher or None)
            local_node=getattr(original_interface,"localNode",None); module_config=getattr(local_node,"moduleConfig",None); mqtt=getattr(module_config,"mqtt",None)
            if local_node is None or mqtt is None: return self._result("BLOCKED_MQTT_CONFIG_NOT_LOADED",target_transport=target,publisher_node_id=publisher)
            if bool(getattr(mqtt,"enabled",False)) is not True: return self._result("BLOCKED_MQTT_DISABLED",target_transport=target,publisher_node_id=publisher)
            if bool(getattr(mqtt,"proxy_to_client_enabled",False))==desired_proxy:
                return self._result("ALREADY_"+target,target_transport=target,publisher_node_id=publisher,verified=True,feed_generation=original_generation)
            snapshot=copy.deepcopy(mqtt)
            send_lock=getattr(bridge,"send_lock",None)
            if send_lock is None: return self._result("BLOCKED_SEND_LOCK_UNAVAILABLE",target_transport=target,publisher_node_id=publisher)
            self.in_progress=True; self.unverified=True
            with send_lock:
                if not bridge.online or bridge.interface is not original_interface or getattr(original_interface,"_guto_proxy_generation",None)!=original_generation or self.feed_server.generation!=original_generation:
                    self.in_progress=False; self.unverified=False
                    return self._result("BLOCKED_INTERFACE_GENERATION_CHANGED",target_transport=target,publisher_node_id=publisher)
                if target=="HOST_PROXY":
                    if not self._arm_secure_present() or not self.feed_server.consumer_connected or self.feed_server.consumer_uid!=os.getuid():
                        self.in_progress=False; self.unverified=False
                        return self._result("BLOCKED_STANDBY_PRECONDITION_CHANGED",target_transport=target,publisher_node_id=publisher)
                else:
                    if not self._arm_absent() or self.feed_server.consumer_connected:
                        self.in_progress=False; self.unverified=False
                        return self._result("BLOCKED_ROLLBACK_PRECONDITION_CHANGED",target_transport=target,publisher_node_id=publisher)
                setattr(mqtt,"proxy_to_client_enabled",desired_proxy)
                try:
                    local_node.writeConfig("mqtt"); write_sent=True
                except Exception:
                    return self._result("WRITE_EXCEPTION_UNKNOWN_STATE",target_transport=target,publisher_node_id=publisher,write_sent=True)
            deadline=time.monotonic()+max(0.0,float(reconnect_timeout_seconds)); interval=max(0.001,float(poll_interval_seconds)); fresh=None
            while time.monotonic()<deadline:
                cand=getattr(bridge,"interface",None); gen=getattr(cand,"_guto_proxy_generation",None) if cand is not None else None
                if cand is not None and cand is not original_interface and gen and gen!=original_generation and bridge.online and self.feed_server.generation==gen:
                    fresh=cand; break
                time.sleep(interval)
            if fresh is None: return self._result("RECONNECT_TIMEOUT_UNKNOWN_STATE",target_transport=target,publisher_node_id=publisher,write_sent=write_sent)
            bridge._refresh_identity()
            post_id=canonical_meshtastic_id(getattr(bridge,"local_id",None) or None,node_num=getattr(bridge,"local_num",None) or None)
            if post_id!=expected: return self._result("POST_WRITE_IDENTITY_MISMATCH",target_transport=target,publisher_node_id=post_id or None,write_sent=write_sent)
            post_local=getattr(fresh,"localNode",None); post_module=getattr(post_local,"moduleConfig",None); post_mqtt=getattr(post_module,"mqtt",None)
            has_field=getattr(post_module,"HasField",None)
            try: loaded=bool(callable(has_field) and has_field("mqtt"))
            except Exception: loaded=False
            if not loaded or post_mqtt is None: return self._result("POST_WRITE_MQTT_CONFIG_NOT_LOADED",target_transport=target,publisher_node_id=post_id,write_sent=write_sent)
            if bool(getattr(post_mqtt,"proxy_to_client_enabled",False))!=desired_proxy: return self._result("POST_WRITE_TARGET_NOT_VERIFIED",target_transport=target,publisher_node_id=post_id,write_sent=write_sent)
            if not self._mqtt_non_target_equal(snapshot,post_mqtt): return self._result("POST_WRITE_NON_TARGET_DELTA",target_transport=target,publisher_node_id=post_id,write_sent=write_sent)
            self.unverified=False
            gen=getattr(fresh,"_guto_proxy_generation",None)
            return self._result("TRANSPORT_VERIFIED_"+target,target_transport=target,publisher_node_id=post_id,write_sent=write_sent,verified=True,feed_generation=gen)
        except Exception:
            return self._result("CONTROL_INTERNAL_ERROR_UNKNOWN_STATE",target_transport=target,publisher_node_id=publisher,write_sent=write_sent)
        finally:
            snapshot=None; self.in_progress=False; lock.release()
