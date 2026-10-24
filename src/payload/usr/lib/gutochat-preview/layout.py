"""Fixed package namespace; no paths or service names from user input."""
import json
import pathlib
import re
import platform

CODE = pathlib.Path('/usr/lib/gutochat-preview')
CONFIG = pathlib.Path('/etc/gutochat-preview')
STATE = pathlib.Path('/var/lib/gutochat-preview')
RUN = pathlib.Path('/run/gutochat-preview')
UNIT_DIR = pathlib.Path('/etc/systemd/system')
SUPPORTED_OS = ('ubuntu', '24.04')

def selection(role, language, username, groupname, uid, gid):
    if role not in ('base','field') or language not in ('nb','en'):
        raise ValueError('INVALID_ROLE_OR_LANGUAGE')
    for name in (username,groupname):
        if not isinstance(name,str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',name):
            raise ValueError('INVALID_ACCOUNT_NAME')
    if type(uid) is not int or type(gid) is not int or uid < 1000 or gid < 1:
        raise ValueError('ORDINARY_ACCOUNT_REQUIRED')
    return dict(role=role,language=language,username=username,groupname=groupname,uid=uid,gid=gid)

def unit_names(role):
    if role not in ('base','field'):raise ValueError('INVALID_ROLE')
    return tuple('gutochat-preview-'+role+'-'+kind+'.service' for kind in ('core','broker'))

def configuration(s, port):
    s=selection(**s)
    if type(port) is not int or not 1024<=port<=65535:raise ValueError('INVALID_PORT')
    folder=STATE/'data'/s['role']
    return {'role':s['role'],'address':1 if s['role']=='base' else 2,
            'node_name':'GuToChat '+s['role'].capitalize(),'station_name':'GuToChat',
            'ui_language':s['language'],'private_radio_enabled':False,
            'meshtastic_radios':[],'meshtastic_gateways':[],
            'api_host':'127.0.0.1','api_port':port,
            'database':str(folder/'core.sqlite'),'contacts_file':str(folder/'contacts.json'),
            'ui_state_file':str(folder/'ui.json'),'offline_map_directory':str(folder/'maps'),
            'map_aprs_database':str(folder/'aprs.sqlite'),'map_aprs_live_enabled':False,
            'map_aprs_headless_enabled':False,'ui_refresh_interval_seconds':60}

def registry(s):
    s=selection(**s);role=s['role']
    return {'schema_version':1,'allowed_uid':s['uid'],'allowed_gid':s['gid'],
            'config_root':str(CONFIG/role),'backup_root':str(STATE/'broker'/role/'backups'),
            'core_file':'config.json','core_unit':unit_names(role)[0],
            'bindings':{},'bound_files':[],'aprs':None}

def units(s):
    s=selection(**s);role=s['role'];config=CONFIG/role/'config.json'
    common='NoNewPrivileges=yes\nPrivateDevices=yes\nDevicePolicy=closed\nRestrictAddressFamilies=AF_UNIX AF_INET\nIPAddressDeny=any\nIPAddressAllow=127.0.0.1/32\nRestart=on-failure\nRestartSec=3\n'
    core=f'[Unit]\nDescription=GuToChat preview core ({role})\n[Service]\nType=simple\nUser={s["username"]}\nGroup={s["groupname"]}\nExecStart=/usr/bin/python3 -I {CODE}/core_entry.py {role}\nWorkingDirectory={STATE}/data/{role}\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n'+common+'[Install]\nWantedBy=multi-user.target\n'
    broker=f'[Unit]\nDescription=GuToChat preview protected installer ({role})\n[Service]\nType=simple\nUser=root\nGroup=root\nRuntimeDirectory=gutochat-preview/{role}\nRuntimeDirectoryMode=0755\nExecStart=/usr/bin/python3 -I {CODE}/broker_entry.py {role}\nProtectHome=yes\nProtectSystem=strict\nReadWritePaths={CONFIG}/{role} {STATE}/broker/{role} {RUN}/{role}\n'+common+'[Install]\nWantedBy=multi-user.target\n'
    return dict(zip(unit_names(role),(core.encode(),broker.encode())))

def os_supported(path=pathlib.Path('/etc/os-release'), machine=None, compatible_path=pathlib.Path('/proc/device-tree/compatible')):
    values={}
    for line in path.read_text().splitlines():
        if '=' in line:
            key,value=line.split('=',1);values[key]=value.strip('"')
    identity=(values.get('ID'),values.get('VERSION_ID'))
    if identity==SUPPORTED_OS:return True
    if identity!=('debian','13') or (machine or platform.machine())!='aarch64':return False
    try:compatible=compatible_path.read_bytes().split(b'\0')
    except OSError:return False
    return any(token.startswith(b'raspberrypi,') for token in compatible)

def encoded(value):return (json.dumps(value,indent=2)+'\n').encode()
