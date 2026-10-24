"""Fixed installed entry. Uses one serial connection and an optional driver."""
import os,pathlib,re,sys
sys.dont_write_bytecode=True
if os.name!='posix' or os.geteuid()==0 or len(sys.argv)!=3:
    raise SystemExit('ORDINARY_USER_ROLE_AND_ROUTE_REQUIRED')
role,route=sys.argv[1:]
if role not in ('base','field') or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',route):
    raise SystemExit('ADAPTER_ARGUMENT_INVALID')
code=pathlib.Path('/usr/lib/gutochat-preview')
sys.path.insert(0,str(code))
from adapter_bootstrap import CODE,DRIVER,protected_read,validate_config,guarded_interface,role_namespace
from adapter_manifest import require
from usb_inventory import observe_path
from protected_module_store import protected
for folder in (CODE,CODE/'app'/role.upper(),DRIVER):protected(folder,True)
path=pathlib.Path('/etc/gutochat-preview')/role/('mesh-'+route+'.json')
cfg=protected_read(path,os.geteuid(),os.getegid())
def identity_check():
    _,observed=observe_path(cfg['meshtastic']['serial_port'])
    return validate_config(cfg,role,route,observed)
band=identity_check()
sys.path.insert(0,str(DRIVER))
sys.path.insert(0,str(CODE/'app'/role.upper()))
role_namespace(CODE/'app'/role.upper())
import meshbridge
meshbridge.ObservedSerialInterface=guarded_interface(meshbridge.ObservedSerialInterface,band,identity_check)
sys.argv=['meshbridge','--config',str(path)]
raise SystemExit(meshbridge.main())
