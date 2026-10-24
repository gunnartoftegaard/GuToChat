"""Internal preview lifecycle. Keeps all user data and configuration on removal."""
import argparse
import hashlib
import json
import os
import pathlib
import socket
import stat
import struct
import subprocess
import sys
import time
import contextlib
sys.dont_write_bytecode=True

@contextlib.contextmanager
def job_lock(path=pathlib.Path('/run/gutochat-preview-admin.lock')):
    import fcntl
    protected(path.parent,True)
    fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o077 or meta.st_nlink!=1:
            raise RuntimeError('ADMIN_LOCK_INVALID')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('ADMIN_JOB_RUNNING') from None
        yield
    finally:os.close(fd)

def protected(path, directory=False):
    path=pathlib.Path(path)
    if not path.is_absolute() or '..' in path.parts:raise RuntimeError('PROTECTED_ABSOLUTE_PATH_REQUIRED')
    for component in [*reversed(path.parents),path]:
        meta=component.lstat()
        if stat.S_ISLNK(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022:
            raise RuntimeError('PROTECTED_PATH_REQUIRED')
    if directory and not path.is_dir():raise RuntimeError('DIRECTORY_REQUIRED')
    return path

def write_new(path, raw, mode=0o600):
    protected(path.parent,True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())

def directory(path,mode=0o755):
    if path.exists() or path.is_symlink():return protected(path,True)
    protected(path.parent,True);path.mkdir(mode=mode);return protected(path,True)

def systemctl(*args,check=True):
    return subprocess.run(['/usr/bin/systemctl',*args],check=check,capture_output=True,text=True,timeout=30)

def module_state(manifest,layout):
    from module_lifecycle import templates,enabled_units,validate_adapter_configs
    role=manifest['selection']['role'];folder=layout.CONFIG/role
    sys.path.insert(0,str(layout.CODE/'runtime'/role.upper()))
    s=layout.selection(**manifest['selection'])
    modules=json.loads(protected(folder/'module_registration.json').read_bytes())
    cfg=json.loads(protected(folder/'config.json').read_bytes())
    registry=json.loads(protected(folder/'registry.json').read_bytes())
    contents=templates(s,cfg,registry,modules,layout)
    adapters={b['config_file']:json.loads(protected(folder/b['config_file']).read_bytes()) for b in registry['bindings'].values()}
    validate_adapter_configs(cfg,s,registry,modules,adapters,layout)
    return cfg,registry,contents,enabled_units(cfg,registry,layout)

def verify_unit_files(manifest, layout):
    expected=set(layout.unit_names(manifest['selection']['role']))
    if (layout.CONFIG/manifest['selection']['role']/'module_registration.json').exists():expected=set(module_state(manifest,layout)[2])
    if set(manifest['units'])!=expected:raise RuntimeError('UNIT_REGISTRATION_INVALID')
    for name,digest in manifest['units'].items():
        path=layout.UNIT_DIR/name
        if not path.exists() and not path.is_symlink():continue
        protected(path)
        if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('UNIT_MODIFIED_REVIEW_REQUIRED')

def deactivate(role,layout):
    path=layout.CONFIG/role/'installation.json'
    if not path.exists() and not path.is_symlink():return {'role':role,'state':'NOT_CONFIGURED','data_preserved':True}
    manifest=json.loads(protected(path).read_bytes())
    if set(manifest)!={'schema_version','selection','units'} or manifest['schema_version']!=1:
        raise RuntimeError('INSTALLATION_REGISTRATION_INVALID')
    s=layout.selection(**manifest['selection'])
    if s['role']!=role:raise RuntimeError('ROLE_REGISTRATION_INVALID')
    verify_unit_files(manifest,layout)  # Validate every file before stopping any service.
    for name in reversed(list(manifest['units'])):
        path=layout.UNIT_DIR/name
        if path.exists():
            systemctl('stop',name);systemctl('disable',name)
            # Recheck after service operations before deleting the known file.
            verify_unit_files(manifest,layout);path.unlink()
    systemctl('daemon-reload')
    return {'role':role,'state':'DEACTIVATED','data_preserved':True,'configuration_preserved':True}

def wait_for_broker(endpoint,timeout=15):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                sock.settimeout(1);sock.connect(str(endpoint))
                _,uid,_=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if uid!=0:raise RuntimeError('BROKER_PEER_NOT_ROOT')
                return
        except OSError:time.sleep(.1)
    raise RuntimeError('BROKER_READY_TIMEOUT')

def activate(role,layout):
    import grp,pwd
    cfgdir=layout.CONFIG/role
    if not (cfgdir/'installation.json').exists():raise RuntimeError('REGISTRATION_MISSING')
    manifest=json.loads(protected(cfgdir/'installation.json').read_bytes())
    if set(manifest)!={'schema_version','selection','units'} or manifest['schema_version']!=1:
        raise RuntimeError('INSTALLATION_REGISTRATION_INVALID')
    s=layout.selection(**manifest['selection'])
    if s['role']!=role:raise RuntimeError('ROLE_REGISTRATION_INVALID')
    account=pwd.getpwnam(s['username'])
    if (account.pw_uid,account.pw_gid,grp.getgrgid(account.pw_gid).gr_name)!=(s['uid'],s['gid'],s['groupname']):
        raise RuntimeError('REGISTERED_ACCOUNT_CHANGED')
    if not layout.os_supported():raise RuntimeError('PREVIEW_REQUIRES_SUPPORTED_OS')
    import dependency_probe
    if not dependency_probe.check()['ready']:raise RuntimeError('DEPENDENCIES_MISSING')
    modular=(cfgdir/'module_registration.json').exists()
    if modular:
        cfg,registry,contents,enabled=module_state(manifest,layout)
        port=cfg.get('api_port')
    else:
        cfg=json.loads(protected(cfgdir/'config.json').read_bytes());port=cfg.get('api_port')
        if cfg!=layout.configuration(s,port):raise RuntimeError('CORE_ONLY_CONFIGURATION_REQUIRED')
        if json.loads(protected(cfgdir/'registry.json').read_bytes())!=layout.registry(s):raise RuntimeError('REGISTRY_CHANGED')
        contents=layout.units(s);enabled={name:True for name in contents}
    data=layout.STATE/'data'/role
    if data.is_symlink() or data.stat().st_uid!=s['uid']:raise RuntimeError('DATA_OWNER_CHANGED')
    if manifest['units']!={name:hashlib.sha256(raw).hexdigest() for name,raw in contents.items()}:
        raise RuntimeError('UNIT_TEMPLATE_CHANGED_REVIEW_REQUIRED')
    verify_unit_files(manifest,layout)
    try:
        for name,raw in contents.items():
            path=layout.UNIT_DIR/name
            if not path.exists():
                if systemctl('show','--property=FragmentPath','--value',name).stdout.strip():raise RuntimeError('UNIT_ALREADY_REGISTERED')
                write_new(path,raw,0o644)
        systemctl('daemon-reload')
        for name in contents:
            systemctl('enable' if enabled[name] else 'disable',name)
            if enabled[name]:systemctl('start',name)
            else:systemctl('stop',name)
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=1) as sock:
                    sock.sendall(b'{"command":"status"}\n')
                    with sock.makefile('rb') as stream:reply=json.loads(stream.readline(32769))
                if reply.get('ok') is True:break
            except (OSError,ValueError):pass
            time.sleep(.2)
        else:raise RuntimeError('CORE_HEALTH_CHECK_FAILED')
        wait_for_broker(layout.RUN/role/'control.sock')
        for name in contents:
            state=systemctl('is-active',name,check=False).stdout.strip()
            if state!=('active' if enabled[name] else 'inactive'):raise RuntimeError('SERVICE_NOT_ACTIVE')
    except BaseException:
        deactivate(role,layout)
        raise
    return {'role':role,'language':s['language'],'state':'INSTALLED','data_preserved':True,'radio_modules':sorted(registry['bindings']) if modular else [],'publication':'OFF'}

def setup(role,language,username,layout):
    import grp,pwd
    account=pwd.getpwnam(username);group=grp.getgrgid(account.pw_gid)
    s=layout.selection(role,language,account.pw_name,group.gr_name,account.pw_uid,account.pw_gid)
    if not layout.os_supported():raise RuntimeError('PREVIEW_REQUIRES_SUPPORTED_OS')
    protected(layout.CODE,True)
    sys.path.insert(0,str(layout.CODE))
    import dependency_probe
    if not dependency_probe.check()['ready']:raise RuntimeError('DEPENDENCIES_MISSING')
    cfgdir=layout.CONFIG/role;data=layout.STATE/'data'/role;broker=layout.STATE/'broker'/role
    # No overwrite, migration, or merging with any pre-existing configuration/data.
    for path in (cfgdir,data,broker):
        if path.exists() or path.is_symlink():raise RuntimeError('EXISTING_INSTALLATION_REVIEW_REQUIRED')
    for name in layout.unit_names(role):
        path=layout.UNIT_DIR/name
        if path.exists() or path.is_symlink() or systemctl('show','--property=FragmentPath','--value',name).stdout.strip():
            raise RuntimeError('UNIT_ALREADY_EXISTS')
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    for path in (layout.CONFIG,layout.STATE,layout.STATE/'data',layout.STATE/'broker',cfgdir,broker,broker/'jobs',broker/'backups'):
        directory(path)
    # Create both data directories while root-owned; relinquish ownership afterwards.
    directory(data,0o700);directory(data/'maps',0o700)
    os.chown(data/'maps',s['uid'],s['gid']);os.chown(data,s['uid'],s['gid'])
    write_new(cfgdir/'config.json',layout.encoded(layout.configuration(s,port)),0o640)
    os.chown(cfgdir/'config.json',0,s['gid'])
    write_new(cfgdir/'registry.json',layout.encoded(layout.registry(s)))
    contents=layout.units(s)
    manifest={'schema_version':1,'selection':s,'units':{name:hashlib.sha256(raw).hexdigest() for name,raw in contents.items()}}
    write_new(cfgdir/'installation.json',layout.encoded(manifest))
    return activate(role,layout)

def main():
    if os.geteuid()!=0:raise RuntimeError('ADMINISTRATOR_REQUIRED')
    code=protected(pathlib.Path(__file__).absolute()).parent
    if code!=pathlib.Path('/usr/lib/gutochat-preview'):raise RuntimeError('PACKAGE_ENTRY_REQUIRED')
    for filename in ('layout.py','dependency_probe.py','module_lifecycle.py','adapter_manifest.py'):protected(code/filename)
    sys.path.insert(0,str(code))
    import layout
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('setup');p.add_argument('role',choices=('base','field'));p.add_argument('language',choices=('nb','en'));p.add_argument('username')
    p=sub.add_parser('deactivate');p.add_argument('role',choices=('base','field','all'))
    p=sub.add_parser('resume');p.add_argument('role',choices=('base','field'))
    p=sub.add_parser('register-radio');p.add_argument('role',choices=('base','field'));p.add_argument('usb_id');p.add_argument('route');p.add_argument('label');p.add_argument('band',choices=('433','868'));p.add_argument('port',type=int);p.add_argument('channel',type=int)
    args=parser.parse_args()
    with job_lock():
        if args.action=='setup':result=setup(args.role,args.language,args.username,layout)
        elif args.action=='resume':result=activate(args.role,layout)
        elif args.action=='register-radio':
            for name in ('module_commission.py','module_install.py','protected_module_store.py','usb_inventory.py','driver_probe.py'):protected(code/name)
            from module_commission import register
            result=register(args.role,args.usb_id,args.route,args.label,args.band,args.port,args.channel,layout)
        else:result={'roles':[deactivate(role,layout) for role in (('base','field') if args.role=='all' else (args.role,))]}
    print(json.dumps(result))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'state':'FAILED','error_type':type(error).__name__,'reason':str(error) if isinstance(error,RuntimeError) else 'OPERATION_FAILED'}));raise SystemExit(1)
