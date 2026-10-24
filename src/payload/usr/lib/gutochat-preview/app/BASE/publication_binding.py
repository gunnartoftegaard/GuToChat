"""Trusted installer-side APRS binding transaction; never load from GUI config."""
import ast,copy,hashlib,json,os,pathlib,re,stat
from contextlib import contextmanager
from activation import ActivationError,encode,digest,replace_file,write_exclusive
from device_setup import validate_selection,selection_from_config

def patched_helper(source,old_config,new_config):
    text=source.decode('utf-8');ast.parse(text)
    matches=list(re.finditer(r'^EXPECTED_CONFIG_SHA256 = "([0-9a-f]{64})"$',text,re.M))
    if len(matches)!=1 or matches[0].group(1)!=digest(old_config):raise ActivationError('APRS_TRUSTED_BASELINE_MISMATCH')
    match=matches[0];new=digest(new_config)
    candidate=text[:match.start(1)]+new+text[match.end(1):]
    ast.parse(candidate)
    if candidate[:match.start(1)]!=text[:match.start(1)] or candidate[match.end(1):]!=text[match.end(1):]:
        raise ActivationError('APRS_HELPER_CHANGE_REJECTED')
    return candidate.encode('utf-8')

def allowed_change(before,after,bindings):
    a=json.loads(before);b=json.loads(after)
    wanted=selection_from_config(b);validate_selection(wanted,b.get('api_port',8765))
    managed={'route_key','key','label','enabled','api_host','api_port','channel_index','capability'}
    old={d.get('route_key') or d.get('key'):d for d in a.get('meshtastic_radios',[])}
    for item in b.get('meshtastic_radios',[]):
        key=item.get('route_key') or item.get('key')
        if key not in bindings or item.get('capability')!=bindings[key]['capability']:
            raise ActivationError('APRS_ADAPTER_IDENTITY_REJECTED')
        remaining={k:v for k,v in item.items() if k not in managed}
        original={k:v for k,v in old.get(key,{}).items() if k not in managed}
        if remaining!=original:raise ActivationError('APRS_DEVICE_FIELD_CHANGE_REJECTED')
    for cfg in (a,b):
        cfg.pop('private_radio_enabled',None);cfg.pop('meshtastic_radios',None)
        if isinstance(cfg.get('meshtastic'),dict):
            for key in ('api_host','api_port','channel_index'):cfg['meshtastic'].pop(key,None)
    if a!=b:raise ActivationError('APRS_NON_SETUP_CHANGE_REJECTED')

class AprsBinding:
    def __init__(self,helper,expected_helper_sha256,config_file,bindings,lock_path,status_reader,
                 *,require_root=True,lock_factory=None):
        self.helper=pathlib.Path(helper);self.expected=expected_helper_sha256
        self.config_file=config_file;self.bindings=copy.deepcopy(bindings)
        self.lock_path=pathlib.Path(lock_path);self.status_reader=status_reader
        self.require_root=require_root;self.lock_factory=lock_factory

    def metadata(self):
        if self.helper.is_symlink() or not self.helper.is_file():raise ActivationError('APRS_HELPER_PATH_REJECTED')
        meta=self.helper.stat()
        if self.require_root:
            if os.name!='posix' or os.geteuid()!=0 or meta.st_uid!=0 or meta.st_gid!=0 or stat.S_IMODE(meta.st_mode)!=0o755:
                raise ActivationError('APRS_ROOT_INSTALLER_REQUIRED')
            parent=self.helper.parent.stat()
            if parent.st_uid!=0 or parent.st_mode&0o022:raise ActivationError('APRS_HELPER_DIRECTORY_REJECTED')
        return stat.S_IMODE(meta.st_mode)

    def state(self):
        value=self.status_reader()
        if not isinstance(value,dict) or value.get('state') not in ('ON','OFF') or value.get('ok') is not True or value.get('changed') is not False:
            raise ActivationError('APRS_CONTROL_NOT_VERIFIED')
        identity=value.get('identity')
        required={'version_ok','build_id_ok','config_sha256_ok','worker_sha256_ok','component_hashes_ok'}
        if not isinstance(identity,dict) or not required.issubset(identity) or any(identity[k] is not True for k in required):
            raise ActivationError('APRS_CONTROL_IDENTITY_REJECTED')
        return value['state']

    def prepare(self,before,after):
        mode=self.metadata();source=self.helper.read_bytes()
        if digest(source)!=self.expected:raise ActivationError('APRS_HELPER_CHANGED')
        allowed_change(before[self.config_file],after[self.config_file],self.bindings)
        candidate=patched_helper(source,before[self.config_file],after[self.config_file])
        return {'old_sha256':digest(source),'new_sha256':digest(candidate),'candidate':candidate,'mode':mode,'state':self.state()}

    def fresh(self,recipe):
        self.metadata()
        if digest(self.helper.read_bytes())!=recipe['old_sha256']:raise ActivationError('APRS_HELPER_CHANGED')
        if self.state()!=recipe['state']:raise ActivationError('APRS_STATE_CHANGED')

    @contextmanager
    def mutation_lock(self):
        if self.lock_factory:
            with self.lock_factory():yield
            return
        if os.name!='posix':raise ActivationError('APRS_LOCK_PLATFORM_UNSUPPORTED')
        import fcntl
        fd=os.open(self.lock_path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            meta=os.fstat(fd)
            if self.require_root and (meta.st_uid!=0 or stat.S_IMODE(meta.st_mode)!=0o600):raise ActivationError('APRS_LOCK_IDENTITY_REJECTED')
            # Refuse a busy APRS operation instead of waiting indefinitely.
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            yield
        finally:os.close(fd)

    def backup(self,folder,recipe):
        self.fresh(recipe)
        source=self.helper.read_bytes()
        write_exclusive(folder/'publication-helper.backup',source)
        if digest((folder/'publication-helper.backup').read_bytes())!=recipe['old_sha256']:raise ActivationError('APRS_BACKUP_MISMATCH')
        return {k:v for k,v in recipe.items() if k!='candidate'}

    def apply(self,recipe):
        self.metadata()
        if digest(self.helper.read_bytes())!=recipe['old_sha256']:raise ActivationError('APRS_HELPER_CHANGED')
        replace_file(self.helper,recipe['candidate'],recipe['mode'])
        if digest(self.helper.read_bytes())!=recipe['new_sha256']:raise ActivationError('APRS_BINDING_WRITE_FAILED')
        if self.state()!=recipe['state']:raise ActivationError('APRS_STATE_CHANGED')

    def validate_restore(self,folder,record):
        self.metadata();backup=folder/'publication-helper.backup'
        if backup.is_symlink():raise ActivationError('APRS_BACKUP_PATH_REJECTED')
        data=backup.read_bytes()
        if digest(data)!=record['old_sha256']:raise ActivationError('APRS_BACKUP_MISMATCH')
        if digest(self.helper.read_bytes()) not in (record['old_sha256'],record['new_sha256']):raise ActivationError('APRS_EXTERNAL_HELPER_CHANGE')
        return data

    def restore(self,folder,record):
        data=self.validate_restore(folder,record)
        replace_file(self.helper,data,record['mode'])
        if digest(self.helper.read_bytes())!=record['old_sha256']:raise ActivationError('APRS_ROLLBACK_MISMATCH')

    def verify_restored(self,record):
        if self.state()!=record['state']:raise ActivationError('APRS_ROLLBACK_STATE_MISMATCH')
