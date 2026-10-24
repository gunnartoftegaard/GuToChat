"""Actual storage and authorization code, synthetic databases; no SDK/radio import."""
import argparse,ast,concurrent.futures,contextlib,functools,importlib.util,json,logging,pathlib,sqlite3,subprocess,sys,tempfile,threading,time,types,unittest
from datetime import datetime
from unittest.mock import Mock
BASE=None
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
@functools.lru_cache(None)
def load(role):
    p=BASE/role
    retry=module('synthetic_retry_'+role,p/'sqlite_resilience.py')
    previous=sys.modules.get('sqlite_resilience');sys.modules['sqlite_resilience']=retry
    try:replay=module('synthetic_replay_'+role,p/'lc3_replay_store.py')
    finally:
        if previous is None:sys.modules.pop('sqlite_resilience',None)
        else:sys.modules['sqlite_resilience']=previous
    store=module('synthetic_messages_'+role,p/'message_store.py')
    tree=ast.parse((p/'meshbridge.py').read_bytes())
    bridge=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='BridgeStore')
    scope=dict(contextmanager=contextlib.contextmanager,sqlite3=sqlite3,time=time,datetime=datetime,Path=pathlib.Path,json=json,LOG=logging.getLogger('synthetic'),BROADCAST_NUM=0xffffffff,MessageStore=store.MessageStore,sqlite_locked_retry=retry.sqlite_locked_retry)
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='now_iso']+[bridge]
    program=ast.Module(body=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0)]+nodes,type_ignores=[])
    exec(compile(ast.fix_missing_locations(program),str(p/'meshbridge.py'),'exec'),scope)
    guards={}
    for n in ast.walk(tree):
        if isinstance(n,ast.FunctionDef) and n.name in ('_remote_status_allowed','_privileged_remote_allowed','_handle_gateway_control'):
            program=ast.Module(body=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0),n],type_ignores=[])
            exec(compile(ast.fix_missing_locations(program),str(p/'meshbridge.py'),'exec'),scope);guards[n.name]=scope[n.name]
    return scope['BridgeStore'],replay.LC3ReplayStore,guards,scope
def enqueue(s,request='synthetic-request',route='synthetic-a'):
    return s.enqueue_gateway_request(request_id=request,route=route,waveshare_source=2,destination='!00000003',channel=0,text='synthetic text',source_label='synthetic source',protocol='LC3',ttl_hours=1)
class MeshRecovery(unittest.TestCase):
    def test_abrupt_process_exit_preserves_commits_and_discards_open_transaction(self):
        worker="""import importlib.util,os,pathlib,sys,time
spec=importlib.util.spec_from_file_location('synthetic_test',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.BASE=pathlib.Path(sys.argv[2])
Store,Replay,_,_=m.load(sys.argv[3]);db=pathlib.Path(sys.argv[4]);s=Store(db);m.enqueue(s);s.mark_gateway_sending('synthetic-request');s.mark_gateway_waiting('synthetic-request','123','synthetic waiting')
now=int(sys.argv[5]);assert Replay(db).check_and_remember('synthetic-key','crash-nonce',now,current_epoch=now,max_skew_seconds=60)
c=s._connect();c.execute('BEGIN IMMEDIATE');c.execute("UPDATE gateway_outbox SET text='UNCOMMITTED'");c.execute('DELETE FROM lc3_auth_replay');os._exit(23)
"""
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                Store,Replay,_,_=load(role);db=pathlib.Path(tmp)/'synthetic.sqlite';now=int(time.time())
                p=subprocess.run([sys.executable,'-I','-B','-c',worker,str(pathlib.Path(__file__).resolve()),str(BASE),role,str(db),str(now)],capture_output=True,text=True,timeout=20)
                self.assertEqual(p.returncode,23,p.stderr)
                s=Store(db);self.assertEqual(s.gateway_request('synthetic-request')['text'],'synthetic text');self.assertEqual(s.gateway_request('synthetic-request')['state'],'waiting_ack')
                self.assertFalse(Replay(db).check_and_remember('synthetic-key','crash-nonce',now,current_epoch=int(time.time()),max_skew_seconds=60))
                self.assertEqual(s.recover_gateway_outbox('synthetic-a'),1)
                self.assertEqual(s.gateway_request('synthetic-request')['state'],'queued')
                with s._connection() as c:self.assertEqual(c.execute('PRAGMA integrity_check').fetchone()[0],'ok')
    def test_replay_marker_survives_store_reopening(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                _,Replay,_,_=load(role);db=pathlib.Path(tmp)/'synthetic.sqlite';now=int(time.time())
                self.assertTrue(Replay(db).check_and_remember('synthetic-key','nonce',now,current_epoch=now,max_skew_seconds=60))
                self.assertFalse(Replay(db).check_and_remember('synthetic-key','nonce',now,current_epoch=now,max_skew_seconds=60))
    def test_concurrent_replay_consumers_accept_exactly_one(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                _,Replay,_,_=load(role);db=pathlib.Path(tmp)/'synthetic.sqlite';stores=[Replay(db) for _ in range(8)];barrier=threading.Barrier(8);now=int(time.time())
                def consume(s):
                    barrier.wait(timeout=5);return s.check_and_remember('synthetic-key','same-nonce',now,current_epoch=now,max_skew_seconds=60)
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(consume,stores))
                self.assertEqual(sum(results),1)
    def test_expired_authenticated_frame_is_not_recorded(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                _,Replay,_,_=load(role);s=Replay(pathlib.Path(tmp)/'synthetic.sqlite');now=int(time.time())
                with self.assertRaisesRegex(ValueError,'expired'):s.check_and_remember('synthetic-key','old',now-1000,current_epoch=now,max_skew_seconds=60)
                with s._connection() as c:self.assertEqual(c.execute('SELECT count(*) FROM lc3_auth_replay').fetchone()[0],0)
    def test_restart_recovers_only_interrupted_route_and_preserves_payload(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                Store,_,_,_=load(role);db=pathlib.Path(tmp)/'synthetic.sqlite';s=Store(db)
                states=('sending','waiting_ack','paused','delivered','sent','failed','expired_hold','queued')
                for state in states:
                    enqueue(s,state)
                    with s._connection() as c:c.execute('UPDATE gateway_outbox SET state=?,packet_id=? WHERE request_id=?',(state,'123',state))
                enqueue(s,'other','synthetic-b')
                with s._connection() as c:c.execute("UPDATE gateway_outbox SET state='waiting_ack' WHERE request_id='other'")
                reopened=Store(db);self.assertEqual(reopened.recover_gateway_outbox('synthetic-a'),2)
                self.assertEqual(reopened.recover_gateway_outbox('synthetic-a'),0)
                for state in states:
                    row=reopened.gateway_request(state);self.assertEqual(row['state'],'queued' if state in ('sending','waiting_ack') else state);self.assertEqual(row['text'],'synthetic text')
                    if state in ('sending','waiting_ack'):self.assertEqual(row['packet_id'],'')
                self.assertEqual(reopened.gateway_request('other')['state'],'waiting_ack')
    def test_recovery_audit_failure_rolls_back_state(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                Store,_,_,_=load(role);s=Store(pathlib.Path(tmp)/'synthetic.sqlite');enqueue(s);s.mark_gateway_sending('synthetic-request')
                with s._connection() as c:c.execute("CREATE TRIGGER synthetic_failure BEFORE INSERT ON queue_events BEGIN SELECT RAISE(ABORT,'synthetic fault'); END")
                with self.assertRaises(sqlite3.IntegrityError):s.recover_gateway_outbox('synthetic-a')
                self.assertEqual(s.gateway_request('synthetic-request')['state'],'sending')
    def test_same_packet_id_is_isolated_by_route_after_reopen(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                Store,_,_,_=load(role);db=pathlib.Path(tmp)/'synthetic.sqlite';s=Store(db)
                for route in ('synthetic-a','synthetic-b'):s.add_pending(packet_id='123',message_uid='uid-'+route,route=route,request_id='request-'+route,waveshare_source=2,destination=3,deadline_epoch=time.time()+60)
                s=Store(db);self.assertEqual(len(s.interrupt_pending('synthetic-a')),1)
                self.assertEqual(s.interrupt_pending('synthetic-a'),[])
                self.assertEqual(s.pop_pending('123','synthetic-b')['message_uid'],'uid-synthetic-b')
    def test_remote_control_requires_each_authorization_condition(self):
        for role in ('BASE',):
            for kind,method in [('control','_privileged_remote_allowed'),('status','_remote_status_allowed')]:
                with self.subTest(role=role,kind=kind):
                    _,_,guards,_=load(role);prefix='remote_base_'+kind
                    values={'role':'base','route_key':'synthetic',prefix+'_enabled':True,prefix:object(),prefix+'_route':'synthetic',prefix+'_field_addresses':{2},kind+'_auth':types.SimpleNamespace(enabled=True)}
                    self.assertTrue(guards[method](types.SimpleNamespace(**values),2,object()))
                    for key,value in [('role','field'),('route_key','wrong'),(prefix+'_enabled',False),(prefix,None),(prefix+'_field_addresses',set()),(kind+'_auth',types.SimpleNamespace(enabled=False))]:
                        altered=dict(values);altered[key]=value;self.assertFalse(guards[method](types.SimpleNamespace(**altered),2,object()))
                    self.assertFalse(guards[method](types.SimpleNamespace(**values),2,None))
    def test_status_authentication_cannot_reach_write_command(self):
        for role in ('BASE',):
            with self.subTest(role=role):
                _,_,guards,scope=load(role)
                scope['parse_control']=lambda text:dict(command='BASE_CONTROL_REQ',route='synthetic')
                auth=types.SimpleNamespace(is_authenticated_frame=lambda text:True,decode_inbound=lambda text,**kw:(text,object()))
                obj=types.SimpleNamespace(route_key='synthetic',status_auth=auth,remote_base_control=Mock())
                self.assertTrue(guards['_handle_gateway_control'](obj,{'source':2,'text':'synthetic'}))
                obj.remote_base_control.handle_control.assert_not_called()
    def test_field_gateway_does_not_execute_base_control(self):
        _,_,guards,scope=load('FIELD')
        self.assertNotIn('_privileged_remote_allowed',guards)
        scope['parse_control']=lambda text:dict(command='BASE_CONTROL_REQ',route='synthetic')
        obj=types.SimpleNamespace(route_key='synthetic',control_auth=types.SimpleNamespace(decode_inbound=lambda text,**kw:(text,object())),_remember_client_protocol=Mock(),remote_base_control=Mock())
        self.assertFalse(guards['_handle_gateway_control'](obj,{'source':2,'text':'synthetic'}))
        obj.remote_base_control.handle_control.assert_not_called()
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('app');args=parser.parse_args();BASE=pathlib.Path(args.app).resolve()
    tempfile.tempdir=str(pathlib.Path.cwd());unittest.main(argv=[sys.argv[0]],verbosity=2)
