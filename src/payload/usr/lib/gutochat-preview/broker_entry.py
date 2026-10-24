"""Protected broker; no trial fault-injection or production registry."""
import os,pathlib,stat,sys
CODE=pathlib.Path('/usr/lib/gutochat-preview')
if os.geteuid()!=0 or len(sys.argv)!=2 or sys.argv[1] not in ('base','field'):
    raise SystemExit('ROOT_AND_ROLE_REQUIRED')
role=sys.argv[1];runtime=CODE/'runtime'/role.upper()
for path in [pathlib.Path(__file__).absolute(),runtime,*runtime.rglob('*')]:
    for component in [*reversed(path.parents),path]:
        meta=component.lstat()
        if stat.S_ISLNK(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022:
            raise SystemExit('PROTECTED_CODE_REQUIRED')
sys.dont_write_bytecode=True;sys.path.insert(0,str(runtime))
from installer_runtime import make_factory
from installer_broker import InstallerBroker
registry,factory=make_factory('/etc/gutochat-preview/'+role+'/registry.json')
InstallerBroker('/run/gutochat-preview/'+role+'/control.sock',
                '/var/lib/gutochat-preview/broker/'+role+'/jobs',
                registry['allowed_uid'],registry['allowed_gid'],
                pathlib.Path(registry['config_root'])/registry['core_file'],
                factory,root_mode=True,exit_timeout=15).serve()
