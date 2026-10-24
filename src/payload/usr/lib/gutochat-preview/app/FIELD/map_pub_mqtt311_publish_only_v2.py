"""Minimal resilient MQTT 3.1.1 publish-only transport.

Connection-resilience changes from v1:
- Advertise MQTT Keep Alive 0 because this transport has no background heartbeat.
- Before a publish on an existing connection, issue PINGREQ and require PINGRESP.
  A stale/peer-closed socket is hard-closed and reconnected before any PUBLISH
  bytes are sent, avoiding replay ambiguity for QoS 0.
- A PUBLISH send failure hard-closes the socket and is propagated without retry.
- DISCONNECT is best-effort; cleanup never propagates a dead-socket exception.

No SUBSCRIBE implementation exists. Production use must remain protected by the
host interlock/arm gate. TLS is supported as an explicit option but the current
B868 contract is non-TLS port 1883.
"""
from __future__ import annotations

import socket
import ssl
import struct
import time


def _s(v):
    b = v.encode("utf-8")
    return struct.pack("!H", len(b)) + b


def _rl(n):
    o = bytearray()
    while True:
        d = n % 128
        n //= 128
        if n:
            d |= 0x80
        o.append(d)
        if not n:
            return bytes(o)


class PublishOnlyMQTT311:
    def __init__(
        self,
        host,
        port,
        username,
        password,
        *,
        tls=False,
        timeout=10,
        socket_factory=None,
    ):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.tls = bool(tls)
        self.timeout = timeout
        self._sock = None
        self._socket_factory = socket_factory

    @property
    def live(self):
        return self._sock is not None

    def _hard_close(self):
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    @staticmethod
    def _recv_exact(sock, size):
        data = bytearray()
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("MQTT_SOCKET_EOF")
            data.extend(chunk)
        return bytes(data)

    def connect(self):
        if self._sock is not None:
            return
        raw = None
        try:
            raw = (self._socket_factory or socket.create_connection)(
                (self.host, self.port), timeout=self.timeout
            )
            if self.tls:
                raw = ssl.create_default_context().wrap_socket(
                    raw, server_hostname=self.host
                )
            raw.settimeout(self.timeout)
            cid = "gutochat-map-pub-host-" + str(int(time.time()))
            flags = 0x02 | 0x80 | 0x40
            # Keep Alive = 0: this client intentionally has no background
            # heartbeat. Existing connections are probed synchronously before
            # each publish instead.
            body = (
                b"\x00\x04MQTT"
                + b"\x04"
                + bytes([flags])
                + struct.pack("!H", 0)
                + _s(cid)
                + _s(self.username)
                + _s(self.password)
            )
            raw.sendall(b"\x10" + _rl(len(body)) + body)
            header = self._recv_exact(raw, 2)
            if header != b"\x20\x02":
                raise RuntimeError("INVALID_CONNACK")
            data = self._recv_exact(raw, 2)
            if data[1] != 0:
                raise RuntimeError("MQTT_CONNACK_" + str(data[1]))
            self._sock = raw
            raw = None
        finally:
            if raw is not None:
                try:
                    raw.close()
                except Exception:
                    pass

    def _probe_existing_connection(self):
        """Probe an already-open socket without sending application payload."""
        if self._sock is None:
            return
        sock = self._sock
        try:
            sock.sendall(b"\xc0\x00")  # PINGREQ
            response = self._recv_exact(sock, 2)
            if response != b"\xd0\x00":
                raise RuntimeError("INVALID_PINGRESP")
        except Exception:
            self._hard_close()
            raise

    def _prepare_for_publish(self):
        if self._sock is None:
            self.connect()
            return
        try:
            self._probe_existing_connection()
        except Exception:
            # No PUBLISH bytes were sent, so reconnecting here cannot duplicate
            # the application payload.
            self.connect()

    def publish(self, *, topic: str, payload: bytes, retained: bool, qos: int):
        if qos != 0:
            raise ValueError("PRODUCTION_QOS_MUST_BE_0")
        if retained:
            raise ValueError("PRODUCTION_RETAIN_MUST_BE_FALSE")
        self._prepare_for_publish()
        body = _s(topic) + bytes(payload)
        try:
            self._sock.sendall(b"\x30" + _rl(len(body)) + body)
        except Exception:
            # Do not retry after PUBLISH starts: with QoS 0 we cannot know
            # whether a partial/complete packet reached the broker.
            self._hard_close()
            raise

    def subscribe(self, *a, **k):
        raise RuntimeError("MQTT_DOWNLINK_NOT_SUPPORTED")

    def disconnect(self):
        sock = self._sock
        self._sock = None
        if sock is None:
            return
        try:
            try:
                sock.sendall(b"\xe0\x00")
            except Exception:
                pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
