"""Protected installation factory. Registration/commissioning is an install-time task."""
import hashlib,json,os,pathlib,re,socket,subprocess,time
from activation import Activation,ActivationError,SystemdServices
from publication_binding import AprsBinding,patched_helper
from installer_security import GuardedEngine,protected_json,protected_path

REGISTRY='/etc/gutochat-installer/registry.json'
def make_factory(registry_path=REGISTRY):
    if os.name!='posix' or os.geteuid()!=0:raise ActivationError('ROOT_BROKER_REQUIRED')
    registry=protected_json(registry_path)
    required={'schema_version','allowed_uid','allowed_gid','config_root','backup_root','core_file','core_unit','bindings','bound_files','aprs'}
    if set(registry)!=required or registry['schema_version']!=1:raise ActivationError('INSTALLER_REGISTRY_INVALID')
    root=pathlib.Path(registry['config_root']);backups=pathlib.Path(registry['backup_root'])
    bindings=registry['bindings'];core_file=registry['core_file'];core_unit=registry['core_unit']
    names=list(dict.fromkeys([core_file]+[b['config_file'] for b in bindings.values()]))
    if any(not isinstance(name,str) or pathlib.Path(name).name!=name for name in names):raise ActivationError('CONFIG_PATH_INVALID')
    if not isinstance(registry['bound_files'],list):raise ActivationError('PUBLICATION_BINDING_POLICY_REQUIRED')
    def guard():
        if protected_json(registry_path)!=registry:raise ActivationError('INSTALLER_REGISTRY_CHANGED')
        protected_path(root,directory=True);protected_path(backups,directory=True)
        for name in names:
            protected_path(root/name)
            config=protected_json(root/name)
            profile=config.get('hardware_profile_path')
            if profile:protected_path(pathlib.Path(profile) if pathlib.Path(profile).is_absolute() else root/profile)
    def factory():
        guard()
        units=[core_unit]+[b['unit'] for b in bindings.values()]
        files={core_unit:core_file,**{b['unit']:b['config_file'] for b in bindings.values()}}
        def probe(unit):
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                try:
                    cfg=protected_json(root/files[unit]);api=cfg if unit==core_unit else cfg['meshtastic']
                    port=api.get('api_port',8765)
                    if type(port) is not int or not 1024<=port<=65535:return False
                    with socket.create_connection(('127.0.0.1',port),timeout=.5) as sock:
                        sock.sendall(b'{"command":"status"}\n')
                        with sock.makefile('rb') as stream:
                            raw=stream.readline(32769)
                            if len(raw)>32768:return False
                            reply=json.loads(raw)
                    if unit==core_unit:
                        if reply.get('ok') is True and isinstance(reply.get('status'),dict):return True
                    else:
                        from adapter_health import healthy
                        registered=next(b for b in bindings.values() if b['unit']==unit)
                        if healthy(reply,registered):return True
                except (OSError,ValueError,KeyError):pass
                time.sleep(.1)
            return False
        services=SystemdServices(units,{u:lambda u=u:probe(u) for u in units})
        binding=None
        if registry['bound_files']:
            spec=registry['aprs']
            if not isinstance(spec,dict) or set(spec)!={'helper','template_sha256','config_file','lock_path'} or set(registry['bound_files'])!={spec['config_file']}:
                raise ActivationError('APRS_REGISTRATION_REQUIRED')
            helper=protected_path(spec['helper']);source=helper.read_bytes()
            normalized=re.sub(rb'(?m)^EXPECTED_CONFIG_SHA256 = "[0-9a-f]{64}"$',b'EXPECTED_CONFIG_SHA256 = "'+b'0'*64+b'"',source)
            if normalized==source or hashlib.sha256(normalized).hexdigest()!=spec['template_sha256']:raise ActivationError('APRS_PROTECTED_CODE_CHANGED')
            if spec['config_file'] not in names:raise ActivationError('APRS_CONFIG_NOT_REGISTERED')
            patched_helper(source,(root/spec['config_file']).read_bytes(),(root/spec['config_file']).read_bytes())
            protected_path(pathlib.Path(spec['lock_path']).parent,directory=True)
            def state():
                protected_path(helper)
                result=subprocess.run([str(helper),'status'],capture_output=True,text=True,timeout=20,check=True)
                if len(result.stdout)>32768:raise ActivationError('APRS_STATUS_LIMIT')
                return json.loads(result.stdout)
            binding=AprsBinding(helper,hashlib.sha256(source).hexdigest(),spec['config_file'],bindings,spec['lock_path'],state)
        elif registry['aprs'] is not None:raise ActivationError('APRS_REGISTRY_INCONSISTENT')
        engine=Activation(root,backups,core_file,core_unit,bindings,services,bound_files=registry['bound_files'],binding=binding)
        return GuardedEngine(engine,guard)
    guard()
    return registry,factory
