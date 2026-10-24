"""Synthetic legacy position upgrades; no live files/radio/network."""
import argparse,contextlib,gc,importlib.util,pathlib,sqlite3,tempfile,threading,types,unittest
BASE=None;OLD=None
def load(path,name):
 m=types.ModuleType(name);exec(compile(path.read_bytes(),str(path),'exec'),m.__dict__);return m.PositionStore
def legacy(path,role):
 old=load(OLD/role/'position_store.py','old_'+role);old(path);gc.collect()
 with contextlib.closing(sqlite3.connect(path)) as c:
  c.execute("INSERT INTO node_positions_history(network,node_id,num,latitude_i,longitude_i,position_epoch,position_time_source,received_at,received_epoch,source,observation_key,stored_at) VALUES ('synthetic','!00000001',1,601000000,104000000,1000,'packet','2026-10-24T00:00:00+00:00',1000,'synthetic','synthetic-key','2026-10-24T00:00:00+00:00')");c.commit()
  columns=[r[1] for r in c.execute('pragma table_info(node_positions_history)')]
  before=c.execute('select '+','.join(columns)+' from node_positions_history').fetchall()
 return columns,before
class Upgrade(unittest.TestCase):
 def test_fresh_and_idempotent_initialization(self):
  for role in ('BASE','FIELD'):
   with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
    db=pathlib.Path(tmp)/'test.sqlite';cls=load(BASE/role/'position_store.py','new_'+role);cls(db);cls(db)
    with contextlib.closing(sqlite3.connect(db)) as c:
     self.assertIn('ingested_epoch',[r[1] for r in c.execute('pragma table_info(node_positions_history)')]);self.assertEqual(c.execute('pragma quick_check').fetchall(),[('ok',)])
 def test_legacy_upgrade_preserves_all_old_values(self):
  for role in ('BASE','FIELD'):
   with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
    db=pathlib.Path(tmp)/'test.sqlite';columns,before=legacy(db,role);load(BASE/role/'position_store.py','new_'+role)(db)
    with contextlib.closing(sqlite3.connect(db)) as c:
     self.assertEqual(c.execute('select '+','.join(columns)+' from node_positions_history').fetchall(),before)
     self.assertIsNone(c.execute('select ingested_epoch from node_positions_history').fetchone()[0])
     self.assertTrue(c.execute("select 1 from sqlite_master where name='idx_position_history_retention_ingested_epoch'").fetchone())
 def test_two_concurrent_legacy_initializations(self):
  for role in ('BASE','FIELD'):
   with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
    db=pathlib.Path(tmp)/'test.sqlite';legacy(db,role);cls=load(BASE/role/'position_store.py','new_'+role);start=threading.Barrier(2);errors=[]
    def run():
     try:start.wait(2);cls(db)
     except Exception as exc:errors.append(str(exc))
    threads=[threading.Thread(target=run) for _ in range(2)]
    for t in threads:t.start()
    for t in threads:t.join(10)
    self.assertFalse(any(t.is_alive() for t in threads));self.assertEqual(errors,[])
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('base',type=pathlib.Path);p.add_argument('old',type=pathlib.Path);p.add_argument('--expect-legacy-fail',action='store_true');a=p.parse_args();BASE=a.base;OLD=a.old
 tmp=pathlib.Path.cwd()/'work/position_upgrade_tmp';tmp.mkdir(parents=True,exist_ok=True);tempfile.tempdir=str(tmp.resolve())
 r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Upgrade))
 if a.expect_legacy_fail:assert len(r.errors)==2 and len(r.failures)==2 and all('ingested_epoch' in message for _,message in r.errors)
 else:assert r.wasSuccessful()
