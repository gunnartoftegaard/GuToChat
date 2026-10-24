"""Secure credential contract loader; emits no secret values."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json, os, stat

SCHEMA='gutochat.map.pub.host.credentials.v1'
@dataclass(frozen=True)
class Credentials:
    node_id:str; broker:str; port:int; username:str; password:str

def load_credentials(path: str, *, expected_node:str, expected_broker:str, expected_port:int, require_secure_metadata:bool=True) -> Credentials:
    p=Path(path)
    st=p.stat()
    if require_secure_metadata:
        if st.st_uid != 0 or st.st_gid != 0: raise PermissionError('CREDENTIAL_OWNER_NOT_ROOT_ROOT')
        if stat.S_IMODE(st.st_mode) != 0o600: raise PermissionError('CREDENTIAL_MODE_NOT_0600')
    x=json.loads(p.read_text(encoding='utf-8'))
    checks=[
      x.get('schema')==SCHEMA,
      str(x.get('source_node_id','')).lower()==expected_node.lower(),
      x.get('broker')==expected_broker,
      int(x.get('port',-1))==int(expected_port),
      bool(x.get('username')), bool(x.get('password')),
    ]
    if not all(checks): raise ValueError('CREDENTIAL_CONTRACT_MISMATCH')
    return Credentials(str(x['source_node_id']),str(x['broker']),int(x['port']),str(x['username']),str(x['password']))
