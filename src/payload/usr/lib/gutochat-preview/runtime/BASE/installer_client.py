"""GUI transport to the fixed local installer endpoint, never to config commands."""
import json,os,pathlib,socket,stat,struct,threading
from activation import ActivationError

ENDPOINT='/run/gutochat-installer/control.sock'
LIMIT=32768

def frame(stream):
    raw=stream.readline(LIMIT+1)
    if len(raw)>LIMIT or not raw.endswith(b'\n'):raise ActivationError('INSTALLER_PROTOCOL_LIMIT')
    try:value=json.loads(raw)
    except (ValueError,UnicodeError):raise ActivationError('INSTALLER_PROTOCOL_INVALID') from None
    if not isinstance(value,dict):raise ActivationError('INSTALLER_PROTOCOL_INVALID')
    return value

class InstallerClient:
    def __init__(self,path,*,expected_uid=0,timeout=3):
        self.path=str(path);self.expected_uid=expected_uid;self.timeout=timeout
        self.registered_adapters=[];self.last_result=None;self.token=None;self.lock=threading.Lock()
    def request(self,value):
        data=(json.dumps(value,separators=(',',':'))+'\n').encode()
        if len(data)>LIMIT:raise ActivationError('INSTALLER_PROTOCOL_LIMIT')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout);sock.connect(self.path)
            _,uid,_=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if uid!=self.expected_uid:raise ActivationError('INSTALLER_PEER_NOT_TRUSTED')
            sock.sendall(data)
            with sock.makefile('rb') as stream:reply=frame(stream)
        if reply.get('ok') is not True:
            reason=reply.get('reason','INSTALLER_REQUEST_FAILED')
            if not isinstance(reason,str) or not reason.isascii() or not reason.replace('_','').isalnum() or not reason.isupper():reason='INSTALLER_REQUEST_FAILED'
            raise ActivationError(reason)
        return reply['result']
    def prepare(self,plan):
        with self.lock:self.token=None
        result=self.request({'operation':'prepare','plan':plan})
        if result.get('state')=='READY':
            with self.lock:self.token=result['token']
        return result
    def invalidate(self):
        # No synchronous IPC on Tk field changes. A cancelled local token cannot be handed off.
        with self.lock:self.token=None
    def handoff(self,token):
        with self.lock:
            if token!=self.token or token is None:raise ActivationError('SETUP_CHECK_REQUIRED')
            self.token=None
        return self.request({'operation':'handoff','token':token})

def connect_installer(config_path):
    if os.name!='posix' or not hasattr(socket,'SO_PEERCRED'):return None
    try:
        from installer_security import protected_path
        path=pathlib.Path(ENDPOINT)
        protected_path(path.parent,directory=True)
        meta=path.lstat()
        if not stat.S_ISSOCK(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o007:return None
        client=InstallerClient(path,timeout=.5)
        result=client.request({'operation':'hello','config_path':str(pathlib.Path(config_path).resolve())})
        client.last_result=result.get('last_result');client.registered_adapters=result.get('registered_adapters',[]);client.timeout=30
        return client
    except (OSError,RuntimeError,ValueError,KeyError):return None
