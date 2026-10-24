#!/usr/bin/env python3
"""Host broker-transport runtime candidate v2. NOT installed/activated by H."""
from __future__ import annotations
import argparse, json, os, socket, time
from pathlib import Path

from app.map_pub_arm_v1 import load_arm
from app.map_pub_credentials_v2 import load_credentials
from app.map_pub_mqtt311_publish_only_v1 import PublishOnlyMQTT311
from app.map_pub_proxy_contract_v2 import DeviceProxyState, HostProxyGate
from app.map_pub_proxy_controller_v2 import ProxyController
from app.map_pub_proxy_feed_v2 import ProxyFeedRecord

EXPECTED_ROOT = "msh/EU_868/NO/Østlandet"

def resolve_systemd_credential(name: str) -> str:
    if not name or "/" in name or name in (".", ".."):
        raise RuntimeError("CREDENTIAL_NAME_INVALID")
    directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not directory:
        raise RuntimeError("SYSTEMD_CREDENTIALS_DIRECTORY_MISSING")
    base = Path(directory).resolve()
    path = (base / name).resolve()
    if path.parent != base:
        raise RuntimeError("CREDENTIAL_PATH_ESCAPE")
    if not path.is_file():
        raise RuntimeError("SYSTEMD_CREDENTIAL_MISSING:" + name)
    return str(path)

def _control_request(obj, host="127.0.0.1", port=8766, timeout=3.0):
    wire=(json.dumps(obj,separators=(",",":"))+"\n").encode("utf-8")
    with socket.create_connection((host,port), timeout=timeout) as s:
        s.sendall(wire)
        line=s.makefile("rb").readline(1024*1024)
    if not line:
        raise RuntimeError("CONTROL_API_EMPTY_RESPONSE")
    return json.loads(line)

def read_device_proxy_state(expected_node: str, *, host="127.0.0.1", port=8766) -> DeviceProxyState:
    try:
        status=_control_request({"command":"status"},host,port).get("status") or {}
        pub=_control_request(
            {"command":"publication_status","expected_node_id":expected_node},host,port
        ).get("publication_status") or {}
        fresh = (
            status.get("online") is True
            and str(status.get("local_id","")).lower() == expected_node.lower()
        )
        return DeviceProxyState(
            publisher_node_id=pub.get("publisher_node_id"),
            identity_match=pub.get("identity_match"),
            mqtt_enabled=pub.get("mqtt_enabled"),
            proxy_to_client_enabled=pub.get("proxy_to_client_enabled"),
            read_source=pub.get("read_source"),
            state_fresh=bool(fresh),
        )
    except Exception:
        return DeviceProxyState(None,None,None,None,None,False)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--feed-socket",required=True)
    ap.add_argument("--credential-name",default="map-pub-host-credentials-v1.json")
    ap.add_argument("--arm-name",default="MAP_PUB_PROXY_ARMED")
    ap.add_argument("--broker",default="mqtt.868.no")
    ap.add_argument("--port",type=int,default=1883)
    ap.add_argument("--node",default="!0400a3ac")
    ap.add_argument("--production-network-enable",action="store_true")
    ap.add_argument("--reconnect-delay",type=float,default=2.0)
    args=ap.parse_args()

    if not args.production_network_enable:
        raise SystemExit("FAIL_CLOSED_PRODUCTION_NETWORK_NOT_EXPLICITLY_ENABLED")

    credential_path=resolve_systemd_credential(args.credential_name)
    arm_path=resolve_systemd_credential(args.arm_name)

    load_arm(
        arm_path, expected_node=args.node, expected_broker=args.broker,
        expected_root=EXPECTED_ROOT, require_secure_metadata=False
    )
    cred=load_credentials(
        credential_path, expected_node=args.node, expected_broker=args.broker,
        expected_port=args.port, require_secure_metadata=False
    )

    broker=PublishOnlyMQTT311(
        cred.broker,cred.port,cred.username,cred.password,tls=False
    )
    gate=HostProxyGate(True,True,True,True,True,True)

    while True:
        ctl=ProxyController(broker,gate)
        s=None
        f=None
        try:
            s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            s.connect(args.feed_socket)
            f=s.makefile("r",encoding="utf-8")
            for line in f:
                if not line.strip():
                    continue
                rec=ProxyFeedRecord.from_mapping(json.loads(line))
                if rec.record_type == "MQTT_CLIENT_PROXY_PUBLISH":
                    ctl.set_device_state(read_device_proxy_state(args.node))
                result=ctl.process(rec)
                print(json.dumps({"result":result},separators=(",",":")),flush=True)
            raise RuntimeError("LOCAL_PROXY_FEED_EOF")
        except Exception as exc:
            if broker.live:
                broker.disconnect()
            print(json.dumps({"result":"FEED_FAIL_CLOSED","reason":type(exc).__name__},
                             separators=(",",":")),flush=True)
            time.sleep(max(args.reconnect_delay,0.2))
        finally:
            if f is not None:
                try: f.close()
                except Exception: pass
            if s is not None:
                try: s.close()
                except Exception: pass

if __name__=="__main__":
    main()
