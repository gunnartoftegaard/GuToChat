"""Explicit host arm-file contract. Missing/invalid file means blocked."""
from __future__ import annotations
from pathlib import Path
import json, stat, time
SCHEMA='gutochat.map.pub.host.arm.v1'
TARGET_SCOPE='FULL_DEVICE_SIDE_MQTT_UPLINK_PARITY_UPLINK_ONLY'
def load_arm(path:str, *, expected_node:str, expected_broker:str, expected_root:str, require_secure_metadata=True) -> dict:
    p=Path(path); st=p.stat()
    if require_secure_metadata:
        if st.st_uid!=0 or st.st_gid!=0: raise PermissionError('ARM_OWNER_NOT_ROOT_ROOT')
        if stat.S_IMODE(st.st_mode)!=0o600: raise PermissionError('ARM_MODE_NOT_0600')
    x=json.loads(p.read_text(encoding='utf-8'))
    if x.get('schema')!=SCHEMA or x.get('armed') is not True: raise ValueError('ARM_NOT_VALID')
    if str(x.get('node_id','')).lower()!=expected_node.lower(): raise ValueError('ARM_NODE_MISMATCH')
    if x.get('broker')!=expected_broker or x.get('root')!=expected_root: raise ValueError('ARM_CONTRACT_MISMATCH')
    if x.get('target_scope')!=TARGET_SCOPE: raise ValueError('ARM_SCOPE_MISMATCH')
    expires=x.get('expires_epoch')
    if expires is not None and int(expires) <= int(time.time()): raise ValueError('ARM_EXPIRED')
    return x
