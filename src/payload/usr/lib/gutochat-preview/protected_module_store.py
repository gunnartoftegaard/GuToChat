"""Root-only bounded file backend for optional-module registration.

No driver downloads or radio access. Administrator entry holds its job lock.
Interrupted journals block new registration until explicit administrator review.
"""
import hashlib,json,os,pathlib,re,socket,stat,struct,subprocess,uuid,time
from adapter_manifest import require


def protected(path,directory=False):
    for item in [*reversed(path.parents),path]:
        meta=item.lstat()
        require(meta.st_uid==0 and not meta.st_mode&0o022 and not stat.S_ISLNK(meta.st_mode),'PROTECTED_PATH_REQUIRED')
        if item!=path:require(stat.S_ISDIR(meta.st_mode),'PROTECTED_PARENT_REQUIRED')
    require(stat.S_ISDIR(meta.st_mode) if directory else stat.S_ISREG(meta.st_mode),'PROTECTED_TYPE_REQUIRED')


class ProtectedStore:
    def __init__(self,role):
        require(os.name=='posix' and os.geteuid()==0,'ROOT_INSTALLER_REQUIRED')
        require(role in ('base','field'),'ROLE_INVALID')
        self.role=role;self.config=pathlib.Path('/etc/gutochat-preview')/role
        self.unit=pathlib.Path('/etc/systemd/system')
        self.backups=pathlib.Path('/var/lib/gutochat-preview/broker')/role/'backups'
        for path in (self.config,self.unit,self.backups):protected(path,True)
        for directory in self.backups.glob('commission-*'):
            protected(directory,True);journal=directory/'journal.json';protected(journal)
            record=json.loads(journal.read_bytes())
            require(record.get('state') in ('COMPLETE_DISABLED','ROLLED_BACK'),'INTERRUPTED_COMMISSION_REVIEW_REQUIRED')
        jobs=self.backups.parent/'jobs';protected(jobs,True)
        for file in jobs.glob('*.json'):
            protected(file);record=json.loads(file.read_bytes())
            terminal=record.get('state') in ('COMPLETE','ROLLED_BACK') or (record.get('state')=='FAILED' and record.get('reason')=='GUI_PROCESS_STILL_RUNNING')
            require(terminal,'EXISTING_INSTALLER_JOB_REQUIRES_REVIEW')
        self.folder=None
    def path(self,space,name):
        require(space in ('config','unit') and isinstance(name,str),'PATH_NAMESPACE_INVALID')
        if space=='config':
            valid=name in ('config.json','installation.json','registry.json','module_registration.json') or re.fullmatch(r'mesh-[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\.json',name)
        else:valid=name in ('gutochat-preview-'+self.role+'-core.service','gutochat-preview-'+self.role+'-broker.service') or re.fullmatch(r'gutochat-preview-'+self.role+r'-mesh-[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\.service',name)
        require(valid,'FILE_NAME_INVALID')
        parent=self.config if space=='config' else self.unit;protected(parent,True)
        return parent/name
    def read(self,space,name):
        path=self.path(space,name)
        if not path.exists() and not path.is_symlink():return None
        protected(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            meta=os.fstat(f.fileno());require(meta.st_uid==0 and stat.S_ISREG(meta.st_mode) and not meta.st_mode&0o022 and meta.st_size<=131072,'PROTECTED_FILE_INVALID')
            return {'raw':f.read(),'mode':stat.S_IMODE(meta.st_mode),'gid':meta.st_gid}
    def write(self,space,name,meta,expected):
        require(set(meta)=={'raw','mode','gid'} and isinstance(meta['raw'],bytes) and len(meta['raw'])<=131072,'FILE_METADATA_INVALID')
        require(meta['mode'] in (0o600,0o640,0o644) and type(meta['gid']) is int and meta['gid']>=0,'FILE_PERMISSIONS_INVALID')
        path=self.path(space,name);require(self.read(space,name)==expected,'FILE_CHANGED_SINCE_PREPARE')
        temporary=path.with_name(path.name+'.commission-'+uuid.uuid4().hex)
        fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,meta['mode'])
        try:
            with os.fdopen(fd,'wb') as f:
                os.fchown(f.fileno(),0,meta['gid']);os.fchmod(f.fileno(),meta['mode']);f.write(meta['raw']);f.flush();os.fsync(f.fileno())
            require(self.read(space,name)==expected,'FILE_CHANGED_DURING_WRITE')
            os.replace(temporary,path);self.sync(path.parent)
        finally:
            if temporary.exists():temporary.unlink()
    def remove(self,space,name,expected):
        require(self.read(space,name)==expected,'FILE_CHANGED_BEFORE_REMOVE')
        path=self.path(space,name);path.unlink();self.sync(path.parent)
    @staticmethod
    def sync(directory):
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def backup(self,records):
        self.folder=self.backups/('commission-'+uuid.uuid4().hex);self.folder.mkdir(mode=0o700)
        self.journal({'state':'BACKUP_IN_PROGRESS'})
        metadata=[]
        for (space,name),record in records.items():
            self.path(space,name)
            metadata.append({'space':space,'name':name,'exists':record is not None,'mode':record['mode'] if record else None,'gid':record['gid'] if record else None,'sha256':hashlib.sha256(record['raw']).hexdigest() if record else None})
            if record is not None:
                directory=self.folder/space;directory.mkdir(mode=0o700,exist_ok=True)
                path=directory/name
                fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as f:f.write(record['raw']);f.flush();os.fsync(f.fileno())
                require(path.read_bytes()==record['raw'],'BACKUP_VERIFICATION_FAILED')
        path=self.folder/'backup_metadata.json'
        path.write_text(json.dumps(metadata));os.chmod(path,0o600);self.sync(self.folder)
    def journal(self,record):
        require(self.folder is not None,'BACKUP_REQUIRED')
        path=self.folder/'journal.json';temporary=self.folder/('journal-'+uuid.uuid4().hex)
        fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(record,f);f.flush();os.fsync(f.fileno())
        os.replace(temporary,path);self.sync(self.folder)
    def block_new_operations(self):
        # Nonterminal/failed persisted journal is checked by the next constructor.
        require(self.folder is not None,'COMMISSION_REVIEW_REQUIRED')


class BrokerServices:
    def __init__(self,role,adapter_units):
        require(role in ('base','field'),'ROLE_INVALID')
        self.role=role;self.broker='gutochat-preview-'+role+'-broker.service'
        self.adapters=set(adapter_units)
        require(all(re.fullmatch(r'gutochat-preview-'+role+r'-mesh-[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\.service',n) for n in self.adapters),'SERVICE_NAMESPACE_INVALID')
    @staticmethod
    def command(*args,check=True):return subprocess.run(['/usr/bin/systemctl',*args],capture_output=True,text=True,check=check,timeout=30)
    def snapshot_broker(self):return {'active':self.command('is-active',self.broker,check=False).stdout.strip()=='active'}
    def stop_broker(self):self.command('stop',self.broker)
    def start_broker(self):self.command('start',self.broker)
    def reload(self):self.command('daemon-reload')
    def adapter_inactive_disabled(self,name):
        require(name in self.adapters,'UNREGISTERED_SERVICE')
        return self.command('is-active',name,check=False).stdout.strip()=='inactive' and self.command('is-enabled',name,check=False).stdout.strip()=='disabled'
    def broker_healthy(self):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if not self.snapshot_broker()['active']:return False
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                    sock.settimeout(1);sock.connect('/run/gutochat-preview/'+self.role+'/control.sock')
                    _,uid,_=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                return uid==0
            except OSError:time.sleep(.1)
        return False
