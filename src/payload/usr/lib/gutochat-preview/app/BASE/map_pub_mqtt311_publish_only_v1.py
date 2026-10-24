"""Minimal MQTT 3.1.1 publish-only transport.

No SUBSCRIBE implementation exists. Production use must be protected by the host
interlock/arm gate. TLS is supported as an explicit option but the current B868
contract is non-TLS port 1883.
"""
from __future__ import annotations
import socket, ssl, struct, time

def _s(v):
    b=v.encode('utf-8'); return struct.pack('!H',len(b))+b

def _rl(n):
    o=bytearray()
    while True:
        d=n%128; n//=128
        if n: d|=0x80
        o.append(d)
        if not n: return bytes(o)

class PublishOnlyMQTT311:
    def __init__(self, host, port, username, password, *, tls=False, timeout=10, socket_factory=None):
        self.host=host; self.port=int(port); self.username=username; self.password=password; self.tls=bool(tls); self.timeout=timeout; self._sock=None; self._socket_factory=socket_factory
    @property
    def live(self): return self._sock is not None
    def connect(self):
        if self._sock is not None: return
        raw=(self._socket_factory or socket.create_connection)((self.host,self.port),timeout=self.timeout)
        if self.tls:
            raw=ssl.create_default_context().wrap_socket(raw,server_hostname=self.host)
        raw.settimeout(self.timeout)
        cid='gutochat-map-pub-host-'+str(int(time.time()))
        flags=0x02|0x80|0x40
        body=b'\x00\x04MQTT'+b'\x04'+bytes([flags])+struct.pack('!H',30)+_s(cid)+_s(self.username)+_s(self.password)
        raw.sendall(b'\x10'+_rl(len(body))+body)
        h=raw.recv(1); l=raw.recv(1)
        if h!=b'\x20' or l!=b'\x02': raw.close(); raise RuntimeError('INVALID_CONNACK')
        data=b''
        while len(data)<2:
            c=raw.recv(2-len(data))
            if not c: raw.close(); raise RuntimeError('CONNACK_EOF')
            data+=c
        if data[1]!=0: raw.close(); raise RuntimeError('MQTT_CONNACK_'+str(data[1]))
        self._sock=raw
    def publish(self, *, topic:str, payload:bytes, retained:bool, qos:int):
        if qos != 0: raise ValueError('PRODUCTION_QOS_MUST_BE_0')
        if retained: raise ValueError('PRODUCTION_RETAIN_MUST_BE_FALSE')
        if self._sock is None: raise RuntimeError('BROKER_NOT_CONNECTED')
        body=_s(topic)+bytes(payload)
        self._sock.sendall(b'\x30'+_rl(len(body))+body)
    def subscribe(self,*a,**k): raise RuntimeError('MQTT_DOWNLINK_NOT_SUPPORTED')
    def disconnect(self):
        if self._sock is not None:
            try: self._sock.sendall(b'\xe0\x00')
            finally:
                try:self._sock.close()
                finally:self._sock=None
