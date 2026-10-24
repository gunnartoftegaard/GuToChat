import sqlite3,pathlib,time,hashlib,json,sys,urllib.parse,shutil
def backup(source,dest,seconds=30,_observer=None):
 source=pathlib.Path(source).resolve();dest=pathlib.Path(dest).resolve()
 if not source.is_file():raise FileNotFoundError(source)
 if shutil.disk_usage(dest.parent).free<1024**3:raise RuntimeError('Less than 1 GiB free; refusing backup')
 dest.mkdir(mode=0o700,parents=False,exist_ok=False)
 target=dest/'snapshot.sqlite';started=time.monotonic();deadline=started+seconds;last_log=[-5.0]
 src=sqlite3.connect(source.as_uri()+'?mode=ro',uri=True,timeout=1)
 dst=None
 try:
  src.execute('PRAGMA query_only=ON')
  if src.execute('PRAGMA journal_mode').fetchone()[0].lower()!='wal':raise RuntimeError('Expected WAL; refusing revised live backup')
  # Pin one WAL read snapshot so concurrent commits cannot restart each batch.
  src.execute('BEGIN')
  src.execute('SELECT name FROM sqlite_schema LIMIT 1').fetchall()
  dst=sqlite3.connect(target)
  def progress(status,remaining,total):
   elapsed=time.monotonic()-started
   if shutil.disk_usage(dest).free<512*1024**2:raise RuntimeError('Less than 512 MiB free; backup aborted')
   if elapsed-last_log[0]>=5 or status==sqlite3.SQLITE_DONE:
    with (dest/'progress.jsonl').open('a') as log:log.write(json.dumps({'elapsed_seconds':round(elapsed,3),'status':status,'remaining_pages':remaining,'total_pages':total})+'\n')
    last_log[0]=elapsed
   if time.monotonic()>deadline:raise TimeoutError('Backup time limit exceeded; partial destination retained, not valid backup')
   if _observer is not None:_observer(status,remaining,total)
  src.backup(dst,pages=128,progress=progress,sleep=0.1)
  checked=dst.execute('PRAGMA integrity_check').fetchall()
  assert checked==[('ok',)],checked
 finally:
  if dst is not None:dst.close()
  src.close()
 record={'source':str(source),'snapshot':str(target),'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'integrity_check':'ok','live_restore_authorized':False,'limits':'Pinned point-in-time copy; may retain WAL while source read transaction is open; not evidence that writers stopped or restart/replay is safe.'}
 (dest/'backup_result.json').write_text(json.dumps(record,indent=2))
 return record
if __name__=='__main__':
 if len(sys.argv) not in [3,4]:raise SystemExit('Usage: backup_tool.py SOURCE NEW_DESTINATION_DIRECTORY [SECONDS]')
 seconds=int(sys.argv[3]) if len(sys.argv)==4 else 30
 if not 1<=seconds<=120:raise SystemExit('SECONDS must be 1..120')
 print(json.dumps(backup(sys.argv[1],sys.argv[2],seconds=seconds),indent=2))
