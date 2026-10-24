"""Authenticated local proposal broker; factory and all paths are trusted inputs."""
import copy,json,os,pathlib,re,select,socket,stat,struct,threading,time,uuid
from activation import ActivationError,encode,replace_file
from device_setup import create_plan
from installer_client import frame
from installer_security import protected_path
from setup_job import run_after_gui_exit

def safe_reason(exc):
    text=str(exc)
    return text if re.fullmatch('[A-Z0-9_]{1,100}',text) else 'INSTALLER_OPERATION_FAILED'

class InstallerBroker:
    def __init__(self,path,jobs,allowed_uid,allowed_gid,config_path,engine_factory,*,root_mode=True,lifetime=300,exit_timeout=60):
        if os.name!='posix' or not hasattr(socket,'SO_PEERCRED') or not hasattr(os,'pidfd_open'):raise ActivationError('LINUX_PEER_IDENTITY_REQUIRED')
        if root_mode and os.geteuid()!=0:raise ActivationError('ROOT_BROKER_REQUIRED')
        if not root_mode and os.geteuid()==0:raise ActivationError('LAB_BROKER_MUST_NOT_BE_ROOT')
        if type(allowed_uid) is not int or allowed_uid<=0 or type(allowed_gid) is not int or allowed_gid<0:raise ActivationError('INSTALLER_USER_INVALID')
        self.path=pathlib.Path(path);self.jobs=pathlib.Path(jobs);self.uid=allowed_uid;self.gid=allowed_gid
        self.config_path=str(pathlib.Path(config_path).resolve());self.factory=engine_factory;self.root_mode=root_mode
        self.lifetime=lifetime;self.exit_timeout=exit_timeout;self.lock=threading.Lock();self.pending={};self.records={};self.busy=False;self.blocked=False
        self.stop_event=threading.Event();self.workers=[];self.sequence=0
        self.check_storage()
        for file in self.jobs.glob('*.json'):
            if file.is_symlink() or not file.is_file():raise ActivationError('INSTALLER_JOB_PATH_INVALID')
            record=json.loads(file.read_bytes())
            if record.get('state') in ('WAITING_FOR_GUI_EXIT','RUNNING'):
                record['state']='INTERRUPTED_REVIEW_REQUIRED';record['reason']='INSTALLER_RESTARTED_DURING_JOB';self.blocked=True
                self.persist(record)
            if record.get('state')=='INTERRUPTED_REVIEW_REQUIRED':self.blocked=True
            self.records[record['job_id']]=record;self.sequence=max(self.sequence,record['sequence'])
    def check_storage(self):
        for directory in (self.path.parent,self.jobs):
            if self.root_mode:protected_path(directory,directory=True)
            elif directory.is_symlink() or not directory.is_dir() or directory.stat().st_uid!=os.geteuid():raise ActivationError('LAB_DIRECTORY_INVALID')
    def persist(self,record):
        self.check_storage()
        if not re.fullmatch('[a-f0-9]{32}',record['job_id']):raise ActivationError('INSTALLER_JOB_ID_INVALID')
        target=self.jobs/(record['job_id']+'.json')
        if target.is_symlink():raise ActivationError('INSTALLER_JOB_PATH_INVALID')
        replace_file(target,encode(record),0o600)
    def latest(self):
        if not self.records:return None
        value=max(self.records.values(),key=lambda r:r['sequence'])
        return {k:value[k] for k in ('state','job_id','reason') if k in value}
    def available(self):
        if self.blocked:raise ActivationError('INTERRUPTED_JOB_REVIEW_REQUIRED')
        if self.busy:raise ActivationError('INSTALLER_JOB_ALREADY_RUNNING')
    def dispatch(self,request,pid,uid):
        if uid!=self.uid:raise ActivationError('INSTALLER_USER_NOT_AUTHORIZED')
        operation=request.get('operation')
        if operation=='hello' and set(request)=={'operation','config_path'}:
            if request['config_path']!=self.config_path:raise ActivationError('INSTALLER_CONFIG_NOT_REGISTERED')
            with self.lock:
                result={'state':'CONNECTED','last_result':self.latest(),'registered_adapters':[]}
                if not self.blocked and not self.busy:
                    from adapter_catalog import catalog
                    engine=self.factory();_,configs=engine.read()
                    actual=engine.engine if hasattr(engine,'engine') else engine
                    result['registered_adapters']=catalog(actual.bindings,configs)
                return result
        if operation=='prepare' and set(request)=={'operation','plan'}:
            with self.lock:
                self.available();self.pending.pop(pid,None)
            engine=self.factory();plan=copy.deepcopy(request['plan'])
            _,configs=engine.read()
            # Use the registered core only. Neither a file nor a service can be selected by the request.
            core=engine.engine.core_file if hasattr(engine,'engine') else engine.core_file
            canonical=create_plan(configs[core],plan['desired'])
            if plan!=canonical:raise ActivationError('INSTALLER_PROPOSAL_NOT_CANONICAL')
            prepared=engine.prepare(canonical)
            if prepared['state']=='NO_CHANGE':return {'state':'NO_CHANGE','changes':[]}
            token=uuid.uuid4().hex
            with self.lock:
                self.available()
                self.pending={p:v for p,v in self.pending.items() if time.monotonic()-v[0]<=self.lifetime}
                if len(self.pending)>=16:raise ActivationError('INSTALLER_PENDING_LIMIT')
                self.pending[pid]=(time.monotonic(),token,canonical,prepared,engine)
            return {'state':'READY','token':token,'changes':canonical['changes']}
        if operation=='handoff' and set(request)=={'operation','token'}:
            with self.lock:
                self.available();pending=self.pending.pop(pid,None)
                if pending is None or request['token']!=pending[1]:raise ActivationError('SETUP_CHECK_REQUIRED')
                if time.monotonic()-pending[0]>self.lifetime:raise ActivationError('SETUP_CHECK_EXPIRED')
                if len(self.records)>=64:raise ActivationError('INSTALLER_RESULT_RETENTION_REVIEW_REQUIRED')
                pending[4].fresh(pending[3])
                # Kernel process handle pins the peer identity against PID reuse.
                process_fd=os.pidfd_open(pid,0)
                job=uuid.uuid4().hex;self.sequence+=1
                record={'state':'WAITING_FOR_GUI_EXIT','job_id':job,'sequence':self.sequence}
                try:self.persist(record)
                except BaseException:os.close(process_fd);raise
                self.records[job]=record;self.busy=True;self.pending.clear()
                worker=threading.Thread(target=self.execute,args=(job,pid,process_fd,pending[2]),daemon=True)
                try:worker.start()
                except BaseException:
                    os.close(process_fd);self.blocked=True;self.busy=False
                    record.update(state='INTERRUPTED_REVIEW_REQUIRED',reason='INSTALLER_WORKER_START_FAILED');self.persist(record);raise
                self.workers.append(worker)
            return {'state':'WAITING_FOR_GUI_EXIT','job_id':job}
        raise ActivationError('INSTALLER_OPERATION_NOT_ALLOWED')
    def execute(self,job,pid,process_fd,plan):
        record=self.records[job]
        def factory():
            with self.lock:
                record['state']='RUNNING';self.persist(record)
            return self.factory()
        try:
            result=run_after_gui_exit(factory,plan,pid,timeout=self.exit_timeout,alive=lambda _:not bool(select.select([process_fd],[],[],0)[0]))
            state=result.get('state')
            if state not in ('COMPLETE','ROLLED_BACK','NO_CHANGE'):raise ActivationError('INSTALLER_RESULT_INVALID')
            with self.lock:record['state']='COMPLETE' if state=='NO_CHANGE' else state
        except BaseException as exc:
            reason=safe_reason(exc)
            with self.lock:
                # Only an unmodified timeout is safe to retry automatically.
                state='FAILED' if record['state']=='WAITING_FOR_GUI_EXIT' and reason=='GUI_PROCESS_STILL_RUNNING' else 'INTERRUPTED_REVIEW_REQUIRED'
                record.update(state=state,reason=reason);self.blocked=state=='INTERRUPTED_REVIEW_REQUIRED'
        finally:
            os.close(process_fd)
            with self.lock:
                try:self.persist(record)
                except BaseException:self.blocked=True
                self.busy=False
    def serve(self):
        self.check_storage()
        if self.path.exists() or self.path.is_symlink():raise ActivationError('INSTALLER_ENDPOINT_ALREADY_EXISTS')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
            server.bind(str(self.path));inode=self.path.lstat().st_ino
            if self.root_mode:os.chown(self.path,0,self.gid)
            os.chmod(self.path,0o660 if self.root_mode else 0o600)
            server.listen(8);server.settimeout(.2)
            try:
                while not self.stop_event.is_set():
                    try:connection,_=server.accept()
                    except socket.timeout:continue
                    with connection:
                        connection.settimeout(3)
                        try:
                            pid,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                            if uid!=self.uid:raise ActivationError('INSTALLER_USER_NOT_AUTHORIZED')
                            with connection.makefile('rb') as stream:request=frame(stream)
                            reply={'ok':True,'result':self.dispatch(request,pid,uid)}
                        except Exception as exc:reply={'ok':False,'reason':safe_reason(exc)}
                        try:connection.sendall((json.dumps(reply,separators=(',',':'))+'\n').encode('utf-8'))
                        except OSError:pass
            finally:
                if self.path.is_socket() and self.path.lstat().st_ino==inode:self.path.unlink()
