"""Fixed root-owned module commission operation. No arbitrary file arguments."""
import hashlib,json,os,pathlib,subprocess
from adapter_manifest import make_recipe,require
from protected_module_store import ProtectedStore,BrokerServices,protected
from usb_inventory import inventory
from module_install import commission

def driver_ready(username):
    root=pathlib.Path('/usr/lib/gutochat-meshtastic-driver')
    protected(root,True);lock=root/'FILES.json';protected(lock)
    files=json.loads(lock.read_bytes())
    require(isinstance(files,dict) and len(files)>0,'DRIVER_MANIFEST_REQUIRED')
    for name,want in files.items():
        relative=pathlib.PurePosixPath(name)
        require(not relative.is_absolute() and '..' not in relative.parts and relative.parts[0]=='python','DRIVER_PATH_INVALID')
        file=root.joinpath(*relative.parts);protected(file)
        require(hashlib.sha256(file.read_bytes()).hexdigest()==want,'DRIVER_FILE_CHANGED')
    p=subprocess.run(['/usr/sbin/runuser','-u',username,'--','/usr/bin/python3','-I','/usr/lib/gutochat-preview/driver_probe.py'],capture_output=True,text=True,timeout=15)
    return p.returncode==0 and p.stdout.strip()=='MESHTASTIC_DRIVER_READY'

def ensure_gui_closed(uid):
    for folder in pathlib.Path('/proc').iterdir():
        if not folder.name.isdigit():continue
        try:
            if folder.stat().st_uid!=uid:continue
            argv=(folder/'cmdline').read_bytes().split(b'\0')
        except (FileNotFoundError,ProcessLookupError):continue
        require(b'/usr/lib/gutochat-preview/gui_entry.py' not in argv,'GUI_PROCESS_STILL_RUNNING')

def register(role,usb_id,route,label,band,port,channel,layout):
    require(os.geteuid()==0,'ROOT_INSTALLER_REQUIRED')
    store=ProtectedStore(role)
    core=json.loads(store.read('config','config.json')['raw'])
    manifest=json.loads(store.read('config','installation.json')['raw'])
    registry=json.loads(store.read('config','registry.json')['raw'])
    s=layout.selection(**manifest['selection'])
    import pwd,grp
    account=pwd.getpwnam(s['username'])
    require((account.pw_uid,account.pw_gid,grp.getgrgid(account.pw_gid).gr_name)==(s['uid'],s['gid'],s['groupname']),'REGISTERED_ACCOUNT_CHANGED')
    ensure_gui_closed(s['uid'])
    expected=layout.units(s)
    require(manifest['units']=={n:hashlib.sha256(raw).hexdigest() for n,raw in expected.items()},'CORE_UNIT_TEMPLATE_CHANGED')
    device={'kind':'meshtastic_usb','usb_id':usb_id,'route_key':route,'label':label,'band':band,'api_port':port,'channel_index':channel}
    deps=lambda:driver_ready(s['username'])
    recipe=make_recipe(core,manifest,registry,[device],inventory(),deps())
    services=BrokerServices(role,list(recipe['units']))
    return commission(recipe,store,services,inventory,deps)
