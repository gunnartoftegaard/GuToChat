"""Ordinary-user adapter bootstrap. No serial access until validation succeeds."""
import json, os, pathlib, re, stat
from adapter_manifest import require

CODE = pathlib.Path('/usr/lib/gutochat-preview')
DRIVER = pathlib.Path('/usr/lib/gutochat-meshtastic-driver/python')

def role_namespace(folder):
    # Production helpers use app.<helper>; bind that namespace to this role's
    # installed tree, never to a working directory or another role.
    import sys,types
    require('app' not in sys.modules, 'APP_NAMESPACE_ALREADY_LOADED')
    package=types.ModuleType('app');package.__path__=[str(folder)]
    sys.modules['app']=package

def protected_read(path, uid, gid):
    for parent in reversed(path.parents):
        m=parent.lstat()
        require(stat.S_ISDIR(m.st_mode) and m.st_uid==0 and not m.st_mode&0o022, 'PROTECTED_PARENT_REQUIRED')
    fd=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        m=os.fstat(stream.fileno())
        require(stat.S_ISREG(m.st_mode) and m.st_uid==0 and m.st_gid==gid and stat.S_IMODE(m.st_mode)==0o640 and m.st_size<=131072, 'ADAPTER_CONFIG_PERMISSIONS_INVALID')
        return json.loads(stream.read())

def validate_config(config, role, route, observation):
    require(role in ('base','field') and isinstance(route,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',route), 'ADAPTER_ARGUMENT_INVALID')
    require(config.get('role')==role and config.get('private_radio_enabled') is False, 'ADAPTER_ROLE_INVALID')
    record=config.get('optional_adapter')
    require(isinstance(record,dict) and set(record)=={'schema_version','band','identity_sha256'} and record['schema_version']==1 and record['band'] in ('433','868'), 'ADAPTER_REGISTRATION_INVALID')
    mesh=config.get('meshtastic')
    require(isinstance(mesh,dict) and mesh.get('route_key')==route and mesh.get('serial_port')==observation['stable_path'] and record['identity_sha256']==observation['identity_sha256'], 'REGISTERED_USB_CHANGED')
    require(mesh.get('api_host')=='127.0.0.1' and type(mesh.get('api_port')) is int and 1024<=mesh['api_port']<=65535 and type(mesh.get('channel_index')) is int and 0<=mesh['channel_index']<=7, 'ADAPTER_ENDPOINT_INVALID')
    require(mesh.get('capability')=='meshtastic_local_'+record['band'], 'ADAPTER_BAND_INVALID')
    require(mesh.get('structured_gateway') is False and mesh.get('forward_inbound_to') is None, 'ADAPTER_FORWARDING_NOT_AUTHORIZED')
    require(not any(config.get(k,False) for k in ('map_aprs_live_enabled','map_aprs_headless_enabled','field_base_parity_enabled','aprs_field_sync_enabled','remote_base_control_enabled','remote_base_status_enabled')), 'ADAPTER_PUBLICATION_NOT_AUTHORIZED')
    require(config.get('database')=='/var/lib/gutochat-preview/data/'+role+'/core.sqlite', 'ADAPTER_DATA_NAMESPACE_INVALID')
    return record['band']

def validate_radio(interface,band):
    """Inspect the existing connection only; never change radio configuration."""
    metadata=getattr(interface,'metadata',None)
    firmware=getattr(metadata,'firmware_version','')
    require(isinstance(firmware,str) and re.match(r'^2\.(7|8)\.[0-9]+(?:[.\-+]|$)',firmware), 'RADIO_FIRMWARE_REVIEW_REQUIRED')
    lora=getattr(getattr(getattr(interface,'localNode',None),'localConfig',None),'lora',None)
    require(lora is not None, 'RADIO_CONFIG_NOT_READ')
    descriptor=lora.DESCRIPTOR.fields_by_name['region'].enum_type
    region=descriptor.values_by_number.get(lora.region)
    allowed={'433':{'EU_433'},'868':{'EU_868','EU_N_868'}}
    require(region is not None and region.name in allowed[band], 'RADIO_REGION_BAND_MISMATCH')
    return {'firmware':firmware,'region':region.name}

def guarded_interface(parent, band, identity_check):
    class Guarded(parent):
        def __init__(self,*args,**kwargs):
            identity_check()
            bind=kwargs.get('_guto_bind_interface')
            if bind is not None:kwargs['_guto_bind_interface']=lambda interface:None
            try:
                super().__init__(*args,**kwargs)
                identity_check()
                self.gutochat_radio_validation=validate_radio(self,band)
                if bind is not None:bind(self)
            except BaseException:
                try:self.close()
                except Exception:pass
                raise
    return Guarded
