#!/usr/bin/env python3
"""Host broker-transport runtime candidate v5.

A2-1.7P closes O1 by making arm revocation latching process-scoped across all
local proxy-feed reconnects.

NOT installed/activated by A2-1.7P.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
import select
import socket
import stat
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
        return DeviceProxyState(None, None, None, None, None, False)


def replace_gate_armed(controller: ProxyController, armed: bool):
    old = controller.gate
    controller.gate = HostProxyGate(
        armed=bool(armed),
        configuration_complete=old.configuration_complete,
        credentials_verified=old.credentials_verified,
        mqtt_contract_verified=old.mqtt_contract_verified,
        implementation_verified=old.implementation_verified,
        feed_healthy=old.feed_healthy,
        architecture=old.architecture,
    )
    if not armed and getattr(controller.broker, "live", False):
        controller.broker.disconnect()
    return controller.gate


@dataclass(frozen=True)
class ArmSourceIdentity:
    dev: int
    ino: int
    size: int
    mtime_ns: int
    uid: int
    gid: int
    mode: int


def read_arm_source_identity(
    path: str,
    *,
    require_secure_metadata: bool = True,
) -> ArmSourceIdentity:
    st = Path(path).stat()
    mode = stat.S_IMODE(st.st_mode)
    if require_secure_metadata:
        if st.st_uid != 0 or st.st_gid != 0:
            raise PermissionError("ARM_SOURCE_OWNER_NOT_ROOT_ROOT")
        if mode != 0o600:
            raise PermissionError("ARM_SOURCE_MODE_NOT_0600")
    return ArmSourceIdentity(
        dev=int(st.st_dev),
        ino=int(st.st_ino),
        size=int(st.st_size),
        mtime_ns=int(st.st_mtime_ns),
        uid=int(st.st_uid),
        gid=int(st.st_gid),
        mode=int(mode),
    )


class ContinuousStateInterlock:
    """Independent device/control-state polling, preserved from A2-1.7L."""

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


class ProcessArmInterlock:
    """Process-scoped arm validity and revocation latch.

    Exactly one instance is created for the host process before the feed
    reconnect loop. A revocation/invalidity sets `_revoked_latched=True`
    permanently for this process. New feed sessions and new ProxyControllers
    reuse this same object and therefore cannot clear the latch.

    Re-arming requires a fresh host process, which also obtains a fresh systemd
    credential snapshot.
    """

    def __init__(
        self,
        arm_credential_path: str,
        arm_source_path: str,
        expected_node: str,
        expected_broker: str,
        expected_root: str,
        *,
        poll_interval: float = 0.5,
        require_source_secure_metadata: bool = True,
        load_arm_fn: Callable[..., dict] = load_arm,
        read_source_identity: Callable[..., ArmSourceIdentity] = read_arm_source_identity,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if poll_interval <= 0:
            raise ValueError("ARM_POLL_INTERVAL_MUST_BE_POSITIVE")
        self.arm_credential_path = arm_credential_path
        self.arm_source_path = arm_source_path
        self.expected_node = expected_node
        self.expected_broker = expected_broker
        self.expected_root = expected_root
        self.poll_interval = float(poll_interval)
        self.require_source_secure_metadata = bool(require_source_secure_metadata)
        self._load_arm = load_arm_fn
        self._read_source_identity = read_source_identity
        self._monotonic = monotonic
        self._next_poll = self._monotonic()
        self._revoked_latched = False

        # Process-start source identity and credential snapshot contract.
        self._source_identity = self._read_source_identity(
            self.arm_source_path,
            require_secure_metadata=self.require_source_secure_metadata,
        )
        self._load_arm(
            self.arm_credential_path,
            expected_node=self.expected_node,
            expected_broker=self.expected_broker,
            expected_root=self.expected_root,
            require_secure_metadata=False,
        )

    @property
    def revoked_latched(self) -> bool:
        return self._revoked_latched

    def _latch_unarmed(self, controller: ProxyController):
        self._revoked_latched = True
        return replace_gate_armed(controller, False)

    def poll(self, controller: ProxyController, *, force: bool = False):
        now = self._monotonic()
        if not force and now < self._next_poll:
            return None
        self._next_poll = self._monotonic() + self.poll_interval

        if self._revoked_latched:
            replace_gate_armed(controller, False)
            return False

        try:
            self._load_arm(
                self.arm_credential_path,
                expected_node=self.expected_node,
                expected_broker=self.expected_broker,
                expected_root=self.expected_root,
                require_secure_metadata=False,
            )
            current = self._read_source_identity(
                self.arm_source_path,
                require_secure_metadata=self.require_source_secure_metadata,
            )
            if current != self._source_identity:
                self._latch_unarmed(controller)
                return False
        except Exception:
            self._latch_unarmed(controller)
            return False

        replace_gate_armed(controller, True)
        return True

    def seconds_until_poll(self) -> float:
        return max(0.0, self._next_poll - self._monotonic())


def run_feed_session(
    feed_socket: socket.socket,
    controller: ProxyController,
    expected_node: str,
    process_arm_interlock: ProcessArmInterlock,
    *,
    state_poll_interval: float = 0.5,
    control_host: str = "127.0.0.1",
    control_port: int = 8766,
    control_timeout: float = 1.0,
    read_state: Callable[..., DeviceProxyState] = read_device_proxy_state,
    emit: Optional[Callable[[str], None]] = None,
):
    """Run one feed session using a process-persistent arm interlock."""
    if emit is None:
        emit = lambda result: print(
            json.dumps({"result": result}, separators=(",", ":")), flush=True
        )

    state_monitor = ContinuousStateInterlock(
        controller,
        expected_node,
        poll_interval=state_poll_interval,
        control_host=control_host,
        control_port=control_port,
        control_timeout=control_timeout,
        read_state=read_state,
    )
    buffer = bytearray()

    # A new feed session cannot process traffic before the process-scoped arm
    # latch and the device state have both been freshly applied to this
    # session's controller.
    process_arm_interlock.poll(controller, force=True)
    state_monitor.poll(force=True)

    while True:
        timeout = min(
            state_monitor.seconds_until_poll(),
            process_arm_interlock.seconds_until_poll(),
        )
        readable, _, _ = select.select([feed_socket], [], [], timeout)

        # Both execute even on a completely idle feed.
        process_arm_interlock.poll(controller)
        state_monitor.poll()

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
                # No host publish can occur on stale authorization.
                process_arm_interlock.poll(controller, force=True)
                state_monitor.poll(force=True)

            result = controller.process(rec)
            emit(result)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed-socket", required=True)
    ap.add_argument("--credential-name", default="map-pub-host-credentials-v1.json")
    ap.add_argument("--arm-name", default="MAP_PUB_PROXY_ARMED")
    ap.add_argument("--arm-source-path", default="/etc/gutochat/MAP_PUB_PROXY_ARMED")
    ap.add_argument("--broker", default="mqtt.868.no")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--node", default="!0400a3ac")
    ap.add_argument("--production-network-enable", action="store_true")
    ap.add_argument("--reconnect-delay", type=float, default=2.0)
    ap.add_argument("--state-poll-interval", type=float, default=0.5)
    ap.add_argument("--arm-poll-interval", type=float, default=0.5)
    ap.add_argument("--control-timeout", type=float, default=1.0)
    args = ap.parse_args()

    if not args.production_network_enable:
        raise SystemExit("FAIL_CLOSED_PRODUCTION_NETWORK_NOT_EXPLICITLY_ENABLED")
    if args.state_poll_interval <= 0:
        raise SystemExit("FAIL_CLOSED_STATE_POLL_INTERVAL_INVALID")
    if args.arm_poll_interval <= 0:
        raise SystemExit("FAIL_CLOSED_ARM_POLL_INTERVAL_INVALID")
    if args.control_timeout <= 0:
        raise SystemExit("FAIL_CLOSED_CONTROL_TIMEOUT_INVALID")

    credential_path = resolve_systemd_credential(args.credential_name)
    arm_path = resolve_systemd_credential(args.arm_name)

    cred = load_credentials(
        credential_path,
        expected_node=args.node,
        expected_broker=args.broker,
        expected_port=args.port,
        require_secure_metadata=False,
    )

    # Created exactly once for the host process, before the feed reconnect loop.
    process_arm_interlock = ProcessArmInterlock(
        arm_path,
        args.arm_source_path,
        args.node,
        args.broker,
        EXPECTED_ROOT,
        poll_interval=args.arm_poll_interval,
        require_source_secure_metadata=True,
    )

    broker = PublishOnlyMQTT311(
        cred.broker, cred.port, cred.username, cred.password, tls=False
    )
    base_gate = HostProxyGate(True, True, True, True, True, True)

    while True:
        ctl = ProxyController(broker, base_gate)
        s = None
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(args.feed_socket)
            run_feed_session(
                s,
                ctl,
                args.node,
                process_arm_interlock,
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
