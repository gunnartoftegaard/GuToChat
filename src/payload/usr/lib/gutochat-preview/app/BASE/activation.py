"""Controlled configuration transactions for installer-registered adapters.

Registry and service adapter are trusted installer inputs, never proposal fields.
No hardware discovery, package installation or privilege escalation is performed.
"""
import copy
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import uuid
from device_setup import create_plan, selection_from_config
from hardware_profile_runtime import resolve_runtime_config
from capabilities import capability_enabled, network_capability_allowed

class ActivationError(RuntimeError):
    pass

ACTIVE_LOCKS=set()

def owner_alive(pid):
    if type(pid) is not int or pid<=0:raise ActivationError('LOCK_OWNER_INVALID')
    if os.name=='nt':
        import ctypes
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.OpenProcess.restype=ctypes.c_void_p
        handle=kernel.OpenProcess(0x1000,False,pid)
        if not handle:return ctypes.get_last_error()!=87  # Access denied is treated as alive.
        try:
            code=ctypes.c_ulong()
            if not kernel.GetExitCodeProcess(ctypes.c_void_p(handle),ctypes.byref(code)):return True
            return code.value==259
        finally:kernel.CloseHandle(ctypes.c_void_p(handle))
    try:os.kill(pid,0);return True
    except ProcessLookupError:return False
    except PermissionError:return True

def digest(data):
    return hashlib.sha256(data).hexdigest()

def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode('utf-8')

def write_exclusive(path, data, mode=0o600):
    fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, mode)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())

def replace_file(path, data, mode):
    try:previous=path.stat()
    except FileNotFoundError:previous=None
    temp=path.with_name(path.name+'.transaction-'+uuid.uuid4().hex)
    try:
        write_exclusive(temp,data,mode)
        if previous is not None and os.name=='posix' and os.geteuid()==0:os.chown(temp,previous.st_uid,previous.st_gid)
        os.chmod(temp,mode)
        os.replace(temp,path)
        if os.name=='posix':
            fd=os.open(path.parent,os.O_RDONLY)
            try:os.fsync(fd)
            finally:os.close(fd)
    finally:
        if temp.exists():temp.unlink()

class SystemdServices:
    """No sudo/shell; only fixed installer-registered unit names are accepted."""
    def __init__(self,units,health_checks=None,*,scope="system"):
        if scope not in ("system","user"):raise ActivationError("SERVICE_SCOPE_INVALID")
        self.scope=scope
        import re
        self.units=frozenset(units)
        self.health_checks=health_checks or {}
        if any(not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*\.service',u) for u in self.units):
            raise ActivationError('INVALID_SERVICE_UNIT')
    def check_access(self):
        if os.name!="posix":raise ActivationError("LINUX_SERVICE_MANAGER_REQUIRED")
        if self.scope=="system" and os.geteuid()!=0:raise ActivationError("ADMINISTRATOR_BACKEND_REQUIRED")
        if self.scope=="user" and os.geteuid()==0:raise ActivationError("NONROOT_USER_MANAGER_REQUIRED")
    def run(self,unit,*args,check=True):
        if unit not in self.units:raise ActivationError('UNREGISTERED_SERVICE')
        if args and args[0] in ('stop','start','enable','disable'):self.check_access()
        return subprocess.run(['systemctl',*(['--user'] if self.scope=='user' else []),*args,unit],capture_output=True,text=True,timeout=30,check=check)
    def snapshot(self,unit):
        active=self.run(unit,'is-active',check=False).stdout.strip()
        enabled=self.run(unit,'is-enabled',check=False).stdout.strip()
        if active not in ('active','inactive') or enabled not in ('enabled','disabled'):
            raise ActivationError('SERVICE_STATE_UNSUPPORTED')
        return {'active':active=='active','enabled':enabled=='enabled'}
    def stop(self,unit):self.run(unit,'stop')
    def start(self,unit):self.run(unit,'start')
    def set_enabled(self,unit,value):self.run(unit,'enable' if value else 'disable')
    def healthy(self,unit):
        if unit not in self.health_checks:raise ActivationError('APPLICATION_HEALTH_PROBE_REQUIRED')
        return self.snapshot(unit)['active'] and bool(self.health_checks[unit]())

def _usb_metadata_record(path):
    """Read a bounded root-owned udev record without following file symlinks."""
    for parent in reversed(path.parents):
        meta=parent.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022:
            raise ActivationError('USB_METADATA_NOT_TRUSTED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_mode&0o022 or before.st_nlink!=1 or before.st_size>65536:
            raise ActivationError('USB_METADATA_NOT_TRUSTED')
        raw=stream.read(65537)
        after=os.fstat(stream.fileno())
    if len(raw)>65536 or (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns):
        raise ActivationError('USB_CHANGED_DURING_OBSERVATION')
    return raw


def _usb_kernel_present(major,minor):
    """Require a current kernel character-device object, not just stale udev."""
    root=pathlib.Path('/sys/dev/char')
    for parent in [*reversed(root.parents),root]:
        meta=parent.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022:
            raise ActivationError('USB_METADATA_NOT_TRUSTED')
    link=root/(str(major)+':'+str(minor))
    if not link.is_symlink():return False
    target=link.resolve(strict=True)
    if not target.is_relative_to('/sys/devices'):raise ActivationError('USB_METADATA_NOT_TRUSTED')
    return _usb_metadata_record(target/'dev').strip()==(str(major)+':'+str(minor)).encode('ascii')


def _stable_usb_metadata(value):
    """PrivateDevices hides /dev nodes; kernel/udev metadata remains readable.

    Preserve the broker's private /dev and closed device policy. Return only
    the kernel device number for an exact registered stable link. Adapter
    bootstrap still checks actual USB identity before opening the radio.
    """
    if os.name!='posix':raise ActivationError('USB_DEVICE_NOT_AVAILABLE')
    import re
    root=pathlib.Path('/run/udev/data')
    records=list(root.glob('c*:*'))
    if len(records)>8192:raise ActivationError('USB_METADATA_LIMIT')
    matches=[]
    for record in records:
        match=re.fullmatch(r'c([0-9]+):([0-9]+)',record.name)
        if match is None:continue
        raw=_usb_metadata_record(record)
        if ('S:'+value.removeprefix('/dev/')).encode('utf-8') not in raw.splitlines():continue
        major,minor=map(int,match.groups())
        if not _usb_kernel_present(major,minor):continue
        if _usb_metadata_record(record)!=raw or not _usb_kernel_present(major,minor):
            raise ActivationError('USB_CHANGED_DURING_OBSERVATION')
        matches.append(os.makedev(major,minor))
    if len(matches)!=1:raise ActivationError('USB_DEVICE_NOT_AVAILABLE' if not matches else 'USB_IDENTITY_AMBIGUOUS')
    return matches[0]


def stable_usb(path):
    value=str(path)
    if not value.startswith(('/dev/serial/by-path/','/dev/serial/by-id/')) or '..' in pathlib.PurePosixPath(value).parts:
        raise ActivationError('STABLE_USB_MAPPING_REQUIRED')
    target=pathlib.Path(value)
    if target.is_symlink() and target.exists() and stat.S_ISCHR(target.stat().st_mode):
        return target.stat().st_rdev
    try:return _stable_usb_metadata(value)
    except ActivationError:raise
    except (OSError,ValueError,OverflowError):raise ActivationError('USB_DEVICE_NOT_AVAILABLE') from None


class Activation:
    def __init__(self,config_root,backup_root,core_file,core_unit,bindings,services,
                 *,bound_files=None,usb_check=stable_usb,profile_resolver=resolve_runtime_config,private_radio_check=None,binding=None):
        self.root=pathlib.Path(config_root).resolve()
        self.backups=pathlib.Path(backup_root).resolve()
        self.core_file=core_file;self.core_unit=core_unit
        self.bindings=copy.deepcopy(bindings);self.services=services
        if bound_files is None:raise ActivationError('PUBLICATION_BINDING_POLICY_REQUIRED')
        self.bound_files=frozenset(bound_files)
        self.usb_check=usb_check;self.profile_resolver=profile_resolver
        self.private_radio_check=private_radio_check
        self.binding=binding
        self.names=list(dict.fromkeys([core_file]+[b['config_file'] for b in bindings.values()]))
        self.units=[core_unit]+[b['unit'] for b in bindings.values()]
        if len(set(self.units))!=len(self.units):raise ActivationError('DUPLICATE_SERVICE')
        for name in self.names:self.path(name)

    def path(self,name):
        if not isinstance(name,str) or pathlib.Path(name).name!=name or name in ('','.','..'):
            raise ActivationError('CONFIG_PATH_INVALID')
        path=self.root/name
        if path.is_symlink() or path.resolve().parent!=self.root:
            raise ActivationError('CONFIG_PATH_ESCAPE')
        return path

    def read(self):
        data={name:self.path(name).read_bytes() for name in self.names}
        configs={name:json.loads(raw) for name,raw in data.items()}
        if any(not isinstance(cfg,dict) for cfg in configs.values()):raise ActivationError('CONFIG_ROOT_INVALID')
        return data,configs

    def prepare(self,plan):
        access=getattr(self.services,"check_access",None)
        if access is not None:access()
        data,configs=self.read();core=configs[self.core_file]
        if plan.get('schema_version')!=1 or plan.get('state')!='DRAFT_NOT_APPLIED' or plan.get('role')!=core.get('role','unknown'):
            raise ActivationError('PROPOSAL_INVALID')
        if plan.get('baseline')!=selection_from_config(core):raise ActivationError('STALE_PROPOSAL')
        # Recompute changes instead of trusting any action or path in the proposal.
        checked=create_plan(core,plan.get('desired',{}))
        wanted=checked['desired']
        if set(wanted)!= {'private_radio_enabled','meshtastic_radios'}:
            raise ActivationError('UNSUPPORTED_SELECTION_FIELD')
        fields={'route_key','label','enabled','api_host','api_port','channel_index'}
        if any(set(item)!=fields for item in wanted['meshtastic_radios']):raise ActivationError('UNSUPPORTED_DEVICE_FIELD')
        if not checked['changes']:
            self.profile_resolver(core,self.path(self.core_file))
            return {'state':'NO_CHANGE','hashes':{n:digest(b) for n,b in data.items()}}
        selected={item['route_key']:item for item in wanted['meshtastic_radios']}
        if set(selected)-self.bindings.keys():raise ActivationError('ADAPTER_INSTALLATION_REQUIRED')
        if set(d['route_key'] for d in selection_from_config(core)['meshtastic_radios'])-self.bindings.keys():
            raise ActivationError('EXISTING_ADAPTER_NOT_REGISTERED')
        if not wanted['private_radio_enabled'] and any(d.get('enabled',True) for d in core.get('meshtastic_gateways',[])):
            raise ActivationError('PRIVATE_GATEWAY_DEPENDENCY')
        candidate=copy.deepcopy(configs)
        proposed=candidate[self.core_file]
        old={item.get('route_key') or item.get('key'):item for item in core.get('meshtastic_radios',[])}
        proposed['private_radio_enabled']=wanted['private_radio_enabled']
        proposed['meshtastic_radios']=[]
        used_usb=set();usb={};identities=set()
        for item in wanted['meshtastic_radios']:
            key=item['route_key'];binding=self.bindings[key]
            descriptor=copy.deepcopy(old.get(key,{}));descriptor.update(item)
            descriptor['capability']=binding['capability']
            proposed['meshtastic_radios'].append(descriptor)
            bridge=candidate[binding['config_file']].get('meshtastic')
            if not isinstance(bridge,dict) or bridge.get('route_key')!=key:
                raise ActivationError('ADAPTER_CONFIG_IDENTITY_MISMATCH')
            if bridge.get('serial_port')!=binding['serial_port']:
                raise ActivationError('USB_BINDING_MISMATCH')
            if item['enabled']:
                identity=self.usb_check(binding['serial_port'])
                if binding['serial_port'] in used_usb:raise ActivationError('DUPLICATE_USB_DEVICE')
                if identity is not None and identity in identities:raise ActivationError('DUPLICATE_USB_DEVICE')
                used_usb.add(binding['serial_port'])
                if identity is not None:identities.add(identity)
                usb[binding['serial_port']]=identity
            bridge.update(api_host='127.0.0.1',api_port=item['api_port'],channel_index=item['channel_index'])
        runtime=self.profile_resolver(proposed,self.path(self.core_file))
        if not capability_enabled(runtime,'gui') or (wanted['private_radio_enabled'] and not capability_enabled(runtime,'private_lora')):
            raise ActivationError('PROFILE_CAPABILITY_REQUIRED')
        private_identity=None
        if wanted['private_radio_enabled']:
            if self.private_radio_check is None:raise ActivationError('PRIVATE_ADAPTER_COMMISSIONING_REQUIRED')
            private_identity=self.private_radio_check(runtime)
        for item in proposed['meshtastic_radios']:
            if item['enabled'] and not network_capability_allowed(runtime,'mesh_local',item)[0]:
                raise ActivationError('PROFILE_CAPABILITY_REQUIRED')
        profiles={name:self.profile_resolver(cfg,self.path(name)).get('_hardware_profile_runtime') for name,cfg in candidate.items()}
        # Unchanged files retain their original bytes, formatting and permissions.
        new={name:encode(cfg) if cfg!=configs[name] else data[name] for name,cfg in candidate.items()}
        changed={name:raw for name,raw in new.items() if raw!=data[name]}
        binding_recipe=None
        if self.bound_files.intersection(changed):
            if self.binding is None:raise ActivationError('PUBLICATION_BINDING_TRANSACTION_REQUIRED')
            if self.bound_files.intersection(changed)!={self.binding.config_file}:raise ActivationError('PUBLICATION_BINDING_SCOPE_REJECTED')
            binding_recipe=self.binding.prepare(data,new)
        if not changed:return {'state':'NO_CHANGE','hashes':{n:digest(b) for n,b in data.items()}}
        return {'state':'PREPARED','hashes':{n:digest(b) for n,b in data.items()},'new':new,
                'changed':list(changed),'binding':binding_recipe,'usb':usb,'profiles':profiles,'private_identity':private_identity,
                'enabled':{b['unit']:bool(selected.get(key,{}).get('enabled',False)) for key,b in self.bindings.items()}}

    def fresh(self,prepared):
        for name,expected in prepared['hashes'].items():
            if digest(self.path(name).read_bytes())!=expected:raise ActivationError('CONFIG_CHANGED_SINCE_PREPARE')

    def journal(self,folder,record):
        replace_file(folder/'journal.json',encode(record),0o600)

    def apply(self,prepared):
        if self.binding is not None:
            with self.binding.mutation_lock():return self._apply(prepared)
        return self._apply(prepared)

    def _apply(self,prepared):
        access=getattr(self.services,"check_access",None)
        if access is not None:access()
        if prepared.get('state')=='NO_CHANGE':self.fresh(prepared);return {'state':'NO_CHANGE'}
        if prepared.get('state')!='PREPARED':raise ActivationError('NOT_PREPARED')
        # A process-level lock excludes concurrent invocations; stale locks require manual review.
        self.backups.mkdir(mode=0o700,parents=True,exist_ok=True)
        lock=self.backups/'activation.lock'
        write_exclusive(lock,encode({'pid':os.getpid()}))
        ACTIVE_LOCKS.add(str(self.backups))
        folder=None;record=None
        try:
            self.fresh(prepared)
            if prepared.get('binding'):self.binding.fresh(prepared['binding'])
            for path,identity in prepared['usb'].items():
                if self.usb_check(path)!=identity:raise ActivationError('USB_CHANGED_SINCE_PREPARE')
            for name,raw in prepared['new'].items():
                runtime=self.profile_resolver(json.loads(raw),self.path(name))
                if runtime.get('_hardware_profile_runtime')!=prepared['profiles'][name]:raise ActivationError('PROFILE_CHANGED_SINCE_PREPARE')
                if name==self.core_file and runtime.get('private_radio_enabled',True):
                    if self.private_radio_check is None or self.private_radio_check(runtime)!=prepared['private_identity']:
                        raise ActivationError('PRIVATE_RADIO_CHANGED_SINCE_PREPARE')
            before={u:self.services.snapshot(u) for u in self.units}
            if not before[self.core_unit]['active']:raise ActivationError('CORE_MUST_BE_RUNNING')
            folder=self.backups/('activation-'+uuid.uuid4().hex);folder.mkdir(mode=0o700)
            modes={};raw={}
            for name in self.names:
                path=self.path(name);raw[name]=path.read_bytes();modes[name]=stat.S_IMODE(path.stat().st_mode)
                write_exclusive(folder/name,raw[name])
                if digest((folder/name).read_bytes())!=prepared['hashes'][name]:raise ActivationError('BACKUP_HASH_MISMATCH')
            record={'state':'BACKED_UP','before':before,'hashes':prepared['hashes'],'candidate_hashes':{n:digest(b) for n,b in prepared['new'].items()},'changed':prepared['changed'],'modes':modes}
            if prepared.get('binding'):record['binding']=self.binding.backup(folder,prepared['binding'])
            self.journal(folder,record)
            try:
                for unit in reversed(self.units):self.services.stop(unit)
                self.fresh(prepared)
                record['state']='WRITING';self.journal(folder,record)
                for name in prepared['changed']:replace_file(self.path(name),prepared['new'][name],modes[name])
                if prepared.get('binding'):self.binding.apply(prepared['binding'])
                record['state']='STARTING';self.journal(folder,record)
                self.services.start(self.core_unit)
                if not self.services.healthy(self.core_unit):raise ActivationError('CORE_HEALTH_CHECK_FAILED')
                for unit in self.units[1:]:
                    enabled=prepared['enabled'][unit];self.services.set_enabled(unit,enabled)
                    if enabled:
                        self.services.start(unit)
                        if not self.services.healthy(unit):raise ActivationError('ADAPTER_HEALTH_CHECK_FAILED')
                for name,raw in prepared['new'].items():
                    if self.path(name).read_bytes()!=raw:raise ActivationError('POSTCHECK_CONFIG_MISMATCH')
                record['state']='COMPLETE';self.journal(folder,record)
                return {'state':'COMPLETE','backup':str(folder),'changed':prepared['changed']}
            except Exception as error:
                record['failure_type']=type(error).__name__
                self.restore(folder,record)
                return {'state':record['state'],'backup':str(folder),'failure_type':type(error).__name__}
        finally:
            ACTIVE_LOCKS.discard(str(self.backups))
            # Failed rollback keeps the lock to block further automatic operations.
            if not record or record.get('state') in ('COMPLETE','ROLLED_BACK'):lock.unlink()

    def restore(self,folder,record):
        # Verify every backup before touching services or configurations.
        try:
            if any((folder/n).is_symlink() for n in self.names):raise ActivationError('BACKUP_PATH_INVALID')
            raw={n:(folder/n).read_bytes() for n in self.names}
            if any(digest(raw[n])!=record['hashes'][n] for n in self.names):raise ActivationError('BACKUP_HASH_MISMATCH')
            for name in self.names:
                current=digest(self.path(name).read_bytes())
                allowed={record['hashes'][name]}
                if name in record['changed']:allowed.add(record['candidate_hashes'][name])
                if current not in allowed:raise ActivationError('EXTERNAL_CONFIG_CHANGE_REQUIRES_REVIEW')
            if record.get('binding'):
                if self.binding is None:raise ActivationError('APRS_RECOVERY_BACKEND_REQUIRED')
                self.binding.validate_restore(folder,record['binding'])
            record['state']='ROLLING_BACK';self.journal(folder,record)
            for unit in reversed(self.units):self.services.stop(unit)
            for name in self.names:replace_file(self.path(name),raw[name],record['modes'][name])
            if record.get('binding'):
                if self.binding is None:raise ActivationError('APRS_RECOVERY_BACKEND_REQUIRED')
                self.binding.restore(folder,record['binding'])
                self.binding.verify_restored(record['binding'])
            for unit in self.units:
                self.services.set_enabled(unit,record['before'][unit]['enabled'])
                if record['before'][unit]['active']:
                    self.services.start(unit)
                    if not self.services.healthy(unit):raise ActivationError('ROLLBACK_HEALTH_CHECK_FAILED')
            if any(self.path(n).read_bytes()!=raw[n] for n in self.names):raise ActivationError('ROLLBACK_POSTCHECK_FAILED')
            record['state']='ROLLED_BACK';self.journal(folder,record)
        except Exception as error:
            record['state']='ROLLBACK_FAILED';record['rollback_failure_type']=type(error).__name__
            self.journal(folder,record)
            raise ActivationError('ROLLBACK_FAILED') from error

    def recover(self,folder):
        access=getattr(self.services,"check_access",None)
        if access is not None:access()
        if self.binding is not None:
            with self.binding.mutation_lock():return self._recover(folder)
        return self._recover(folder)

    def _recover(self,folder):
        """Explicit recovery after interruption. Never silently resume a transaction."""
        folder=pathlib.Path(folder)
        if folder.is_symlink() or folder.resolve().parent!=self.backups:
            raise ActivationError('BACKUP_PATH_INVALID')
        record=json.loads((folder/'journal.json').read_bytes())
        if record['state'] in ('COMPLETE','ROLLED_BACK'):raise ActivationError('TRANSACTION_ALREADY_FINISHED')
        if set(record['before'])!=set(self.units) or set(record['hashes'])!=set(self.names) or set(record['candidate_hashes'])!=set(self.names) or set(record['modes'])!=set(self.names) or set(record['changed'])-set(self.names):
            raise ActivationError('JOURNAL_REGISTRY_MISMATCH')
        lock=self.backups/'activation.lock'
        if str(self.backups) in ACTIVE_LOCKS:raise ActivationError('ACTIVATION_STILL_RUNNING')
        if lock.exists():
            owner=json.loads(lock.read_bytes()).get('pid')
            if owner!=os.getpid() and owner_alive(owner):raise ActivationError('ACTIVATION_OWNER_STILL_RUNNING')
        else:write_exclusive(lock,encode({'pid':os.getpid()}))
        self.restore(folder.resolve(),record)
        lock.unlink()
        return {'state':record['state'],'backup':str(folder)}
