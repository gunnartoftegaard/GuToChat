"""Isolated synthetic SQLite tests. Never imports radio code or opens a live database."""
import argparse,contextlib,importlib.util,json,pathlib,sqlite3,tempfile,threading,unittest
BASE=None
def load(role):
    spec=importlib.util.spec_from_file_location('store_'+role,BASE/role/'message_store.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.MessageStore
def receive(store,uid='synthetic-1',text='synthetic text'):
    return store.receive_once(message_uid=uid,source=1,destination=2,text=text,packet_rssi=-50,raw_hex=None)
def event(seq,uid):return {'sequence':seq,'payload':{'message_uid':uid,'source':1,'destination':2,'text':'synthetic text'}}
class StorageAtomicity(unittest.TestCase):
    def test_receive_duplicate_and_conflict(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                s=load(role)(pathlib.Path(tmp)/'test.sqlite')
                self.assertFalse(receive(s));self.assertTrue(receive(s))
                with self.assertRaisesRegex(RuntimeError,'conflicts'):receive(s,text='different synthetic text')
                with s._connect() as c:
                    self.assertEqual(c.execute('select count(*) from messages').fetchone()[0],1)
                    self.assertEqual(c.execute('select count(*) from seen_packets').fetchone()[0],1)
    def test_orphan_marker_is_not_acknowledged(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                s=load(role)(pathlib.Path(tmp)/'test.sqlite');s.mark_seen('synthetic-1',1)
                with self.assertRaisesRegex(RuntimeError,'no stored message'):receive(s)
    def test_failed_marker_insert_rolls_back_message(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                s=load(role)(pathlib.Path(tmp)/'test.sqlite')
                with s._connect() as c:c.execute("CREATE TRIGGER synthetic_failure BEFORE INSERT ON seen_packets BEGIN SELECT RAISE(ABORT,'synthetic fault'); END")
                with self.assertRaises(sqlite3.IntegrityError):receive(s)
                with s._connect() as c:
                    self.assertEqual(c.execute('select count(*) from messages').fetchone()[0],0)
                    self.assertEqual(c.execute('select count(*) from seen_packets').fetchone()[0],0)
    def test_field_sync_page_and_cursor_roll_back_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            s=load('FIELD')(pathlib.Path(tmp)/'test.sqlite')
            with self.assertRaises(ValueError):
                s.apply_message_sync_page('synthetic',start_cursor=0,events=[event(1,'synthetic-1'),event(2,'')],final_sequence=2,expected_count=2)
            self.assertEqual(s.message_sync_cursor('synthetic'),0)
            with s._connect() as c:self.assertEqual(c.execute('select count(*) from messages').fetchone()[0],0)
            s.apply_message_sync_page('synthetic',start_cursor=0,events=[event(2,'synthetic-2')],final_sequence=2,expected_count=1)
            self.assertEqual(s.message_sync_cursor('synthetic'),2)
            with self.assertRaisesRegex(ValueError,'cursor changed'):
                s.apply_message_sync_page('synthetic',start_cursor=0,events=[event(1,'synthetic-old')],final_sequence=1)
    def test_two_field_writers_cannot_both_commit_from_same_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            s=load('FIELD')(pathlib.Path(tmp)/'test.sqlite')
            selected=threading.Event();release=threading.Event();high_done=threading.Event();results={}
            original=s._connect
            class Cursor:
                def __init__(self,c):self.c=c
                def fetchone(self):
                    row=self.c.fetchone();selected.set()
                    if not release.wait(4):raise RuntimeError('Synthetic scheduling deadline')
                    return row
            class Connection:
                def __init__(self,c):self.c=c
                def execute(self,sql,*args):
                    cursor=self.c.execute(sql,*args)
                    if threading.current_thread().name=='synthetic-low' and sql.strip().startswith('SELECT remote_sequence FROM message_sync_state'):
                        return Cursor(cursor)
                    return cursor
            @contextlib.contextmanager
            def hooked():
                with original() as c:yield Connection(c)
            s._connect=hooked
            def worker(name,seq):
                try:s.apply_message_sync_page('synthetic',start_cursor=0,events=[event(seq,'synthetic-'+name)],final_sequence=seq);results[name]='committed'
                except ValueError:results[name]='stale_rejected'
                except Exception as exc:results[name]=type(exc).__name__+': '+str(exc)
                finally:
                    if name=='high':high_done.set()
            low=threading.Thread(target=worker,args=('low',1),name='synthetic-low')
            high=threading.Thread(target=worker,args=('high',2),name='synthetic-high')
            low.start();self.assertTrue(selected.wait(3));high.start()
            # Without a write reservation the second writer commits while the first
            # is paused after its cursor read. With one, it must wait and recheck.
            high_done.wait(0.3);release.set();low.join(8);high.join(8)
            self.assertFalse(low.is_alive() or high.is_alive())
            self.assertEqual(sorted(results.values()),['committed','stale_rejected'],results)
            with original() as c:self.assertEqual(c.execute('select count(*) from messages').fetchone()[0],1)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('base',type=pathlib.Path);p.add_argument('--expect-race',action='store_true');a=p.parse_args();BASE=a.base
    temp_root=pathlib.Path.cwd()/'work/storage_atomicity_tmp';temp_root.mkdir(parents=True,exist_ok=True);tempfile.tempdir=str(temp_root.resolve())
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(StorageAtomicity))
    if a.expect_race:
        assert not result.errors and len(result.failures)==1 and result.failures[0][0]._testMethodName=='test_two_field_writers_cannot_both_commit_from_same_cursor'
    else:assert result.wasSuccessful()
