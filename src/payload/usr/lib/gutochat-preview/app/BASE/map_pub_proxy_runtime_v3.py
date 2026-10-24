#!/usr/bin/env python3
"""Host broker-transport runtime candidate v3.

A2-1.7L adds an independent fail-closed control-state monitor so an already-live
host broker connection is disconnected when B868 proxy mode becomes false,
stale, unknown, or unreadable even if no new proxy-feed record arrives.

NOT installed/activated by A2-1.7L.
"""
from __future__ import annotations

import argparse
import json
import os
import select
import socket
import time
from pathlib import Path
from typing import Callable, Optional

from app.map_pub_arm_v1 import load_arm
from app.map_pub_credentials_v2 import load_credentials
from app.map_pub_mqtt311_publish_only_v1 import PublishOnlyMQTT311
from app.map_pub_proxy_contract_v2 import DeviceProxyState, HostProxyGate
from app.map_pub_proxy_controller_v2 import ProxyController
from app.map_pub_proxy_feed_v2 import ProxyFeedRecord

EXPECTED_ROOT = "msh/EU_868/NO/Østlandet"
MAX_FEED_BUFFER = 1024 * 1024


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


def _control_request(obj, host="127.0.0.1", port=8766, timeout=1.0):
    wire = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(wire)
        line = s.makefile("rb").readline(1024 * 1024)
    if not line:
        raise RuntimeError("CONTROL_API_EMPTY_RESPONSE")
    return json.loads(line)


def read_device_proxy_state(
    expected_node: str,
    *,
    host="127.0.0.1",
    port=8766,
    timeout=1.0,
) -> DeviceProxyState:
    try:
        status = _control_request(
            {"command": "status"}, host, port, timeout
        ).get("status") or {}
        pub = _control_request(
            {"command": "publication_status", "expected_node_id": expected_node},
            host,
            port,
            timeout,
        ).get("publication_status") or {}
        fresh = (
            status.get("online") is True
            and str(status.get("local_id", "")).lower() == expected_node.lower()
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
        # Fail closed: controller eligibility blocks this state and disconnects
        # an already-live broker transport.
        return DeviceProxyState(None, None, None, None, None, False)


class ContinuousStateInterlock:
    """Independent control-state polling, not triggered by proxy-feed traffic."""

    def __init__(
        self,
        controller: ProxyController,
        expected_node: str,
        *,
        poll_interval: float = 0.5,
        control_host: str = "127.0.0.1",
        control_port: int = 8766,
        control_timeout: float = 1.0,
        read_state: Callable[..., DeviceProxyState] = read_device_proxy_state,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if poll_interval <= 0:
            raise ValueError("STATE_POLL_INTERVAL_MUST_BE_POSITIVE")
        if control_timeout <= 0:
            raise ValueError("CONTROL_TIMEOUT_MUST_BE_POSITIVE")
        self.controller = controller
        self.expected_node = expected_node
        self.poll_interval = float(poll_interval)
        self.control_host = control_host
        self.control_port = int(control_port)
        self.control_timeout = float(control_timeout)
        self._read_state = read_state
        self._monotonic = monotonic
        self._next_poll = self._monotonic()

    def poll(self, *, force: bool = False):
        now = self._monotonic()
        if not force and now < self._next_poll:
            return None
        device = self._read_state(
            self.expected_node,
            host=self.control_host,
            port=self.control_port,
            timeout=self.control_timeout,
        )
        decision = self.controller.set_device_state(device)
        self._next_poll = self._monotonic() + self.poll_interval
        return decision

    def seconds_until_poll(self) -> float:
        return max(0.0, self._next_poll - self._monotonic())


def run_feed_session(
    feed_socket: socket.socket,
    controller: ProxyController,
    expected_node: str,
    *,
    state_poll_interval: float = 0.5,
    control_host: str = "127.0.0.1",
    control_port: int = 8766,
    control_timeout: float = 1.0,
    read_state: Callable[..., DeviceProxyState] = read_device_proxy_state,
    emit: Optional[Callable[[str], None]] = None,
):
    """Run one connected local feed session.

    State polling continues on the select timeout even when the feed is idle.
    A forced fresh state poll is also performed immediately before each proxy
    PUBLISH record is admitted to the controller.
    """
    if emit is None:
        emit = lambda result: print(
            json.dumps({"result": result}, separators=(",", ":")), flush=True
        )

    monitor = ContinuousStateInterlock(
        controller,
        expected_node,
        poll_interval=state_poll_interval,
        control_host=control_host,
        control_port=control_port,
        control_timeout=control_timeout,
        read_state=read_state,
    )
    buffer = bytearray()

    # Establish a fresh fail-closed state before waiting for any feed traffic.
    monitor.poll(force=True)

    while True:
        timeout = monitor.seconds_until_poll()
        readable, _, _ = select.select([feed_socket], [], [], timeout)

        # This executes even when select timed out with no feed data.
        monitor.poll()

        if not readable:
            continue

        chunk = feed_socket.recv(65536)
        if not chunk:
            raise RuntimeError("LOCAL_PROXY_FEED_EOF")
        buffer.extend(chunk)
        if len(buffer) > MAX_FEED_BUFFER:
            raise RuntimeError("LOCAL_PROXY_FEED_BUFFER_LIMIT")

        while True:
            nl = buffer.find(b"\n")
            if nl < 0:
                break
            raw = bytes(buffer[:nl])
            del buffer[: nl + 1]
            if not raw.strip():
                continue

            rec = ProxyFeedRecord.from_mapping(json.loads(raw.decode("utf-8")))

            if rec.record_type == "MQTT_CLIENT_PROXY_PUBLISH":
                # Preserve the H/J immediate pre-publish state refresh in
                # addition to the new independent periodic monitor.
                monitor.poll(force=True)

            result = controller.process(rec)
            emit(result)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed-socket", required=True)
    ap.add_argument("--credential-name", default="map-pub-host-credentials-v1.json")
    ap.add_argument("--arm-name", default="MAP_PUB_PROXY_ARMED")
    ap.add_argument("--broker", default="mqtt.868.no")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--node", default="!0400a3ac")
    ap.add_argument("--production-network-enable", action="store_true")
    ap.add_argument("--reconnect-delay", type=float, default=2.0)
    ap.add_argument("--state-poll-interval", type=float, default=0.5)
    ap.add_argument("--control-timeout", type=float, default=1.0)
    args = ap.parse_args()

    if not args.production_network_enable:
        raise SystemExit("FAIL_CLOSED_PRODUCTION_NETWORK_NOT_EXPLICITLY_ENABLED")
    if args.state_poll_interval <= 0:
        raise SystemExit("FAIL_CLOSED_STATE_POLL_INTERVAL_INVALID")
    if args.control_timeout <= 0:
        raise SystemExit("FAIL_CLOSED_CONTROL_TIMEOUT_INVALID")

    credential_path = resolve_systemd_credential(args.credential_name)
    arm_path = resolve_systemd_credential(args.arm_name)

    load_arm(
        arm_path,
        expected_node=args.node,
        expected_broker=args.broker,
        expected_root=EXPECTED_ROOT,
        require_secure_metadata=False,
    )
    cred = load_credentials(
        credential_path,
        expected_node=args.node,
        expected_broker=args.broker,
        expected_port=args.port,
        require_secure_metadata=False,
    )

    broker = PublishOnlyMQTT311(
        cred.broker, cred.port, cred.username, cred.password, tls=False
    )
    gate = HostProxyGate(True, True, True, True, True, True)

    while True:
        ctl = ProxyController(broker, gate)
        s = None
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(args.feed_socket)
            run_feed_session(
                s,
                ctl,
                args.node,
                state_poll_interval=args.state_poll_interval,
                control_timeout=args.control_timeout,
            )
        except Exception as exc:
            if broker.live:
                broker.disconnect()
            print(
                json.dumps(
                    {"result": "FEED_FAIL_CLOSED", "reason": type(exc).__name__},
                    separators=(",", ":"),
                ),
                flush=True,
            )
            time.sleep(max(args.reconnect_delay, 0.2))
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass


if __name__ == "__main__":
    main()
