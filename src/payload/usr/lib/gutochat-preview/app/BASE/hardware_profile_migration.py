#!/usr/bin/env python3
"""Fail-closed GuToChat beta4->beta5 hardware-profile config migration.

The migration is deliberately narrow. It accepts only the immutable, known
2.5.0-beta4 Raspberry Pi/Waveshare reference profile and the exact role-bound
beta4 binding. It changes only ``hardware_profile_path`` and
``hardware_binding``. All other config semantics are preserved. Writes use the
candidate's durable atomic-write helper and retain the original file mode.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shlex
import stat
import sys
from pathlib import Path
from typing import Any

SOURCE_PROFILE_REL = Path("hardware_profiles/references/rpi-waveshare-sx126x-reference-v1.1.0-beta4.json")
TARGET_PROFILE_REL = Path("hardware_profiles/references/rpi-waveshare-sx126x-reference-v1.2.0-beta5.json")
SOURCE_PROFILE_SHA256 = "6994775d15ef9bb84c22af61a8509d83797b3bdb8094b1ccdbae9bc9478b7ca4"
SOURCE_BINDING = {
    "base": Path("hardware_profiles/bindings/base-beta4-v1.json"),
    "field": Path("hardware_profiles/bindings/field-beta4-v1.json"),
}
TARGET_BINDING = {
    "base": Path("hardware_profiles/bindings/base-beta5-v1.json"),
    "field": Path("hardware_profiles/bindings/field-beta5-v1.json"),
}
MIGRATION_MODE = "EXACT_BETA4_PROFILE_TO_BETA5_V1"
NO_MIGRATION_MODE = "NONE"

class MigrationError(RuntimeError):
    pass

def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()

def load_obj(path: Path) -> dict[str,Any]:
    try: value=json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc: raise MigrationError(f"JSON_READ_FAILED:{path}:{type(exc).__name__}:{exc}") from exc
    if not isinstance(value,dict): raise MigrationError(f"JSON_OBJECT_REQUIRED:{path}")
    return value

def role_norm(value: Any) -> str:
    role=str(value or '').strip().lower()
    return 'field' if role=='mobile' else role

def _trusted(path: Path, root: Path) -> Path:
    p=path.resolve(strict=True); r=root.resolve(strict=True)
    try: p.relative_to(r)
    except ValueError as exc: raise MigrationError(f"PATH_OUTSIDE_ROOT:{p}") from exc
    if not p.is_file() or p.is_symlink(): raise MigrationError(f"REGULAR_FILE_REQUIRED:{p}")
    return p

def inspect(config_path: Path, live_root: Path, candidate_root: Path, role: str) -> tuple[str,dict[str,Any],dict[str,Any]|None]:
    role=role_norm(role)
    if role not in {'base','field'}: raise MigrationError(f"ROLE_INVALID:{role}")
    cfg=load_obj(config_path)
    cfg_role=role_norm(cfg.get('role'))
    if not cfg_role:
        cfg_role='base' if cfg.get('meshtastic_radios') else 'field'
    if cfg_role!=role: raise MigrationError(f"ROLE_MISMATCH:config={cfg_role}:requested={role}")
    selected=cfg.get('hardware_profile_path')
    binding=cfg.get('hardware_binding')
    if selected is None and binding is None:
        return NO_MIGRATION_MODE,cfg,None
    if not isinstance(selected,str) or not selected.strip(): raise MigrationError('ACTIVE_PROFILE_PATH_REQUIRED')
    if not isinstance(binding,dict): raise MigrationError('ACTIVE_PROFILE_BINDING_OBJECT_REQUIRED')
    source_expected=(live_root/SOURCE_PROFILE_REL).resolve()
    target_live_expected=(live_root/TARGET_PROFILE_REL).resolve()
    try: selected_path=Path(selected).resolve(strict=True)
    except Exception as exc: raise MigrationError(f"ACTIVE_PROFILE_PATH_INVALID:{selected}:{exc}") from exc
    # Already-migrated beta5 config is valid for internal-verify/re-entry, but only
    # when both its profile path and binding exactly match the candidate contract.
    if selected_path == target_live_expected:
        _trusted(selected_path, live_root)
        target_binding=load_obj(_trusted(candidate_root/TARGET_BINDING[role],candidate_root))
        if binding != target_binding:
            raise MigrationError('TARGET_BINDING_NOT_EXACT')
        target_obj=load_obj(selected_path)
        if target_obj.get('profile_id') != target_binding.get('hardware_profile_id') or target_obj.get('profile_version') != target_binding.get('hardware_profile_version'):
            raise MigrationError('TARGET_PROFILE_BINDING_MISMATCH')
        return NO_MIGRATION_MODE,cfg,None
    if selected_path != source_expected:
        raise MigrationError(f"SOURCE_PROFILE_PATH_NOT_EXACT:{selected_path}:expected={source_expected}")
    _trusted(selected_path, live_root)
    if sha256(selected_path) != SOURCE_PROFILE_SHA256:
        raise MigrationError(f"SOURCE_PROFILE_HASH_MISMATCH:{sha256(selected_path)}")
    expected_source_binding=load_obj(_trusted(candidate_root/SOURCE_BINDING[role],candidate_root))
    if binding != expected_source_binding:
        raise MigrationError('SOURCE_BINDING_NOT_EXACT')
    target_profile=_trusted(candidate_root/TARGET_PROFILE_REL,candidate_root)
    target_binding=load_obj(_trusted(candidate_root/TARGET_BINDING[role],candidate_root))
    # The target profile/binding must themselves agree before any migration can be planned.
    target_obj=load_obj(target_profile)
    if target_obj.get('profile_id') != target_binding.get('hardware_profile_id'):
        raise MigrationError('TARGET_PROFILE_BINDING_ID_MISMATCH')
    if target_obj.get('profile_version') != target_binding.get('hardware_profile_version'):
        raise MigrationError('TARGET_PROFILE_BINDING_VERSION_MISMATCH')
    if role_norm(target_binding.get('role')) != role or bool(target_binding.get('legacy_fallback_allowed')):
        raise MigrationError('TARGET_BINDING_SECURITY_CONTRACT_INVALID')
    migrated=copy.deepcopy(cfg)
    migrated['hardware_profile_path']=str((live_root/TARGET_PROFILE_REL).resolve())
    migrated['hardware_binding']=target_binding
    # Prove semantic allowlist: removing the two migration fields leaves the object identical.
    old_rest=copy.deepcopy(cfg); new_rest=copy.deepcopy(migrated)
    old_rest.pop('hardware_profile_path',None); old_rest.pop('hardware_binding',None)
    new_rest.pop('hardware_profile_path',None); new_rest.pop('hardware_binding',None)
    if old_rest != new_rest: raise MigrationError('NON_ALLOWLIST_CONFIG_CHANGE')
    return MIGRATION_MODE,cfg,migrated

def rendered_bytes(config: dict[str,Any]) -> bytes:
    return (json.dumps(config,ensure_ascii=False,indent=2)+"\n").encode('utf-8')

def target_config(mode: str, original: dict[str,Any], migrated: dict[str,Any]|None, *, target: str, live_root: Path, candidate_root: Path) -> dict[str,Any]:
    if mode==NO_MIGRATION_MODE: return original
    assert migrated is not None
    out=copy.deepcopy(migrated)
    if target=='candidate': out['hardware_profile_path']=str((candidate_root/TARGET_PROFILE_REL).resolve())
    elif target=='live': out['hardware_profile_path']=str((live_root/TARGET_PROFILE_REL).resolve())
    else: raise MigrationError(f'TARGET_INVALID:{target}')
    return out

def shell_line(k:str,v:str)->str: return f"{k}={shlex.quote(v)}"

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('command',choices=['plan','render','digest','apply','verify'])
    ap.add_argument('--config',required=True)
    ap.add_argument('--live-root',required=True)
    ap.add_argument('--candidate-root',required=True)
    ap.add_argument('--role',required=True)
    ap.add_argument('--target',choices=['candidate','live'],default='live')
    ap.add_argument('--format',choices=['text','shell'],default='text')
    args=ap.parse_args()
    config_path=Path(args.config).resolve(); live_root=Path(args.live_root).resolve(); candidate_root=Path(args.candidate_root).resolve()
    try: mode,original,migrated=inspect(config_path,live_root,candidate_root,args.role)
    except MigrationError as exc:
        print(f"PROFILE_MIGRATION=FAIL:{exc}",file=sys.stderr); return 1
    target=target_config(mode,original,migrated,target=args.target,live_root=live_root,candidate_root=candidate_root)
    payload=rendered_bytes(target)
    if args.command=='plan':
        vals={
            'PROFILE_MIGRATION_MODE':mode,
            'PROFILE_MIGRATION_REQUIRED':'1' if mode!=NO_MIGRATION_MODE else '0',
            'PROFILE_MIGRATION_TARGET_SHA256':hashlib.sha256(payload).hexdigest(),
            'PROFILE_MIGRATION_TARGET_PROFILE':str(target.get('hardware_profile_path') or ''),
        }
        for k,v in vals.items(): print(shell_line(k,v) if args.format=='shell' else f'{k}={v}')
        return 0
    if args.command=='render':
        sys.stdout.buffer.write(payload); return 0
    if args.command=='digest':
        print(hashlib.sha256(payload).hexdigest()); return 0
    if args.command=='verify':
        actual=load_obj(config_path)
        if actual != target:
            print('PROFILE_MIGRATION_VERIFY=FAIL:semantic_mismatch',file=sys.stderr); return 1
        print(f'PROFILE_MIGRATION_VERIFY=PASS:{mode}'); return 0
    # apply
    if mode==NO_MIGRATION_MODE:
        print('PROFILE_MIGRATION_APPLY=PASS:NONE'); return 0
    from durable_update import atomic_write_bytes
    file_mode=stat.S_IMODE(config_path.stat().st_mode)
    atomic_write_bytes(config_path,payload,file_mode)
    if load_obj(config_path)!=target:
        print('PROFILE_MIGRATION_APPLY=FAIL:postwrite_semantic_mismatch',file=sys.stderr); return 1
    print(f'PROFILE_MIGRATION_APPLY=PASS:{mode}')
    print(f'PROFILE_MIGRATION_CONFIG_SHA256={sha256(config_path)}')
    return 0

if __name__=='__main__': raise SystemExit(main())
