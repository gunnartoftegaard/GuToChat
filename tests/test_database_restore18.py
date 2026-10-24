"""Synthetic maintenance contention and full SQLite snapshot restoration checks.

Uses candidate methods and the previously reviewed pinned backup tool. No live paths.
"""
import argparse,concurrent.futures,contextlib,hashlib,importlib.util,json,pathlib,shutil,sqlite3,sys,tempfile,threading,time,unittest
BASE=None
MESH=None
BACKUP=None
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def activate_protocol(role):sys.modules['protocol']=load_module('synthetic_protocol_'+role,BASE/role/'protocol.py')
def receive(store,uid):
    return store.receive_once(message_uid=uid,source=1,destination=2,text='synthetic '+uid,packet_rssi=-50,raw_hex=None)
def restore_snapshot(snapshot,digest,target):
    """Test harness only: verified bytes, new synthetic destination, never overwrite."""
    if hashlib.sha256(snapshot.read_bytes()).hexdigest()!=digest:raise ValueError('SNAPSHOT_HASH_MISMATCH')
    with target.open('xb') as f:f.write(snapshot.read_bytes())
    with contextlib.closing(sqlite3.connect(target)) as c:
        if c.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:raise ValueError('RESTORED_DATABASE_INTEGRITY_FAILED')
def dump(db):
    with contextlib.closing(sqlite3.connect(db)) as c:return '\n'.join(c.iterdump())
class DatabaseRestore(unittest.TestCase):
    def test_periodic_maintenance_with_concurrent_message_and_mesh_writers(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                activate_protocol(role)
                Store,_,_,_=MESH.load(role);db=pathlib.Path(tmp)/'synthetic.sqlite';bridge=Store(db);messages=MESH.module('synthetic_messages_periodic_'+role,BASE/role/'message_store.py').MessageStore(db)
                barrier=threading.Barrier(3)
                def incoming():
                    barrier.wait(timeout=5)
                    for i in range(40):self.assertFalse(receive(messages,'receive-'+str(i)))
                def outgoing():
                    barrier.wait(timeout=5)
                    for i in range(40):MESH.enqueue(bridge,'queue-'+str(i))
                def periodic():
                    barrier.wait(timeout=5)
                    for i in range(20):self.assertEqual(messages.maintenance(include_integrity=False)['integrity'],'not_run')
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                    jobs=[pool.submit(f) for f in (incoming,outgoing,periodic)]
                    for job in jobs:job.result(timeout=25)
                with bridge._connection() as c:
                    self.assertEqual(c.execute('SELECT count(*) FROM messages').fetchone()[0],40)
                    self.assertEqual(c.execute('SELECT count(*) FROM seen_packets').fetchone()[0],40)
                    self.assertEqual(c.execute('SELECT count(*) FROM gateway_outbox').fetchone()[0],40)
                    self.assertEqual([tuple(r) for r in c.execute('PRAGMA integrity_check')],[('ok',)])
    def test_transient_writer_lock_delays_maintenance_then_allows_it_to_finish(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                activate_protocol(role)
                MessageStore=MESH.module('synthetic_messages_lock_'+role,BASE/role/'message_store.py').MessageStore
                db=pathlib.Path(tmp)/'synthetic.sqlite';s=MessageStore(db);receive(s,'preserved-message')
                reached=threading.Event();original=s._connect
                @contextlib.contextmanager
                def traced():
                    with original() as c:
                        c.set_trace_callback(lambda sql:reached.set() if sql.strip().upper().startswith(('DELETE','UPDATE','INSERT')) else None)
                        yield c
                s._connect=traced
                blocker=sqlite3.connect(db);blocker.execute('BEGIN IMMEDIATE')
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    job=pool.submit(s.maintenance,include_integrity=False)
                    try:
                        self.assertTrue(reached.wait(5),'maintenance did not reach a write');self.assertFalse(job.done())
                    finally:blocker.rollback();blocker.close()
                    self.assertEqual(job.result(timeout=8)['integrity'],'not_run')
                with original() as c:self.assertEqual(c.execute('SELECT text FROM messages').fetchone()[0],'synthetic preserved-message')
    def test_pinned_full_snapshot_restores_store_domains_while_source_advances(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                root=pathlib.Path(tmp);db=root/'source.sqlite';Store,Replay,_,_=MESH.load(role);s=Store(db)
                messages=MESH.module('synthetic_messages_restore_'+role,BASE/role/'message_store.py').MessageStore(db)
                receive(messages,'preserved-message');row,_=MESH.enqueue(s);s.mark_gateway_sending('synthetic-request');s.mark_gateway_waiting('synthetic-request','123','synthetic waiting')
                now=int(time.time());self.assertTrue(Replay(db).check_and_remember('synthetic-key','backup-nonce',now,current_epoch=now,max_skew_seconds=120))
                if role=='FIELD':messages.apply_message_sync_page('synthetic-sync',start_cursor=0,events=[{'sequence':7,'payload':{'message_uid':'synced-synthetic','source':1,'destination':2,'text':'synthetic sync'}}],final_sequence=7,expected_count=1)
                with contextlib.closing(sqlite3.connect(db)) as keeper:
                    keeper.execute('PRAGMA wal_autocheckpoint=0');keeper.execute('CREATE TABLE synthetic_other_domain(id INTEGER PRIMARY KEY,payload BLOB)')
                    keeper.executemany('INSERT INTO synthetic_other_domain(payload) VALUES (?)',[(bytes(8192),)]*150);keeper.commit()
                    keeper.execute('CREATE TABLE synthetic_later_commits(id INTEGER PRIMARY KEY)');keeper.commit()
                    expected=dump(db);writes=[]
                    def advance(status,remaining,total):
                        keeper.execute('INSERT INTO synthetic_later_commits DEFAULT VALUES');keeper.commit();writes.append(1)
                    record=BACKUP.backup(db,root/'backup',seconds=10,_observer=advance)
                    self.assertGreater(len(writes),0)
                    snapshot=root/'backup/snapshot.sqlite';target=root/'restored.sqlite';restore_snapshot(snapshot,record['sha256'],target)
                    self.assertEqual(dump(target),expected)
                    with contextlib.closing(sqlite3.connect(db)) as live:self.assertGreater(live.execute('SELECT count(*) FROM synthetic_later_commits').fetchone()[0],0)
                restored=Store(target)
                self.assertEqual(restored.gateway_request('synthetic-request')['text'],row['text'])
                self.assertEqual(restored.gateway_request('synthetic-request')['state'],'waiting_ack')
                self.assertFalse(Replay(target).check_and_remember('synthetic-key','backup-nonce',now,current_epoch=int(time.time()),max_skew_seconds=120))
                if role=='FIELD':self.assertEqual(MESH.module('synthetic_field_restored',BASE/role/'message_store.py').MessageStore(target).message_sync_cursor('synthetic-sync'),7)
                self.assertEqual(restored.recover_gateway_outbox('synthetic-a'),1)
    def test_changed_snapshot_is_rejected_before_creating_restore_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);source=root/'synthetic.sqlite'
            with contextlib.closing(sqlite3.connect(source)) as c:c.execute('CREATE TABLE synthetic(value TEXT)');c.commit()
            original=hashlib.sha256(source.read_bytes()).hexdigest();source.write_bytes(source.read_bytes()+b'SYNTHETIC_TAMPER')
            target=root/'restored.sqlite'
            with self.assertRaisesRegex(ValueError,'SNAPSHOT_HASH_MISMATCH'):restore_snapshot(source,original,target)
            self.assertFalse(target.exists())
    def test_restore_does_not_overwrite_existing_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);source=root/'synthetic.sqlite'
            with contextlib.closing(sqlite3.connect(source)) as c:c.execute('CREATE TABLE synthetic(value TEXT)');c.commit()
            target=root/'existing.sqlite';target.write_bytes(b'PRESERVE_EXISTING_TARGET')
            with self.assertRaises(FileExistsError):restore_snapshot(source,hashlib.sha256(source.read_bytes()).hexdigest(),target)
            self.assertEqual(target.read_bytes(),b'PRESERVE_EXISTING_TARGET')
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('app');parser.add_argument('mesh_test');parser.add_argument('backup_tool');args=parser.parse_args()
    BASE=pathlib.Path(args.app).resolve();MESH=load_module('synthetic_mesh_test',pathlib.Path(args.mesh_test));MESH.BASE=BASE;BACKUP=load_module('synthetic_backup_tool',pathlib.Path(args.backup_tool))
    tempfile.tempdir=str(pathlib.Path.cwd());unittest.main(argv=[sys.argv[0]],verbosity=2)
