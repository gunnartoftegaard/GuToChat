"""Rebuild the two frozen internal candidate packages. Does not install them."""
import pathlib,json,hashlib,io,tarfile,gzip,argparse,os
def archive(entries):
 stream=io.BytesIO();dirs={'.'}
 for name in entries:
  path=pathlib.PurePosixPath(name);assert not path.is_absolute() and '..' not in path.parts
  dirs.update(p.as_posix() for p in path.parents if p.as_posix()!='.')
 with tarfile.open(fileobj=stream,mode='w',format=tarfile.GNU_FORMAT) as t:
  for directory in sorted(dirs,key=lambda name:(len(pathlib.PurePosixPath(name).parts),name)):
   info=tarfile.TarInfo('./' if directory=='.' else './'+directory+'/');info.type=tarfile.DIRTYPE;info.mode=0o755;info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=0;t.addfile(info)
  for name,(raw,mode) in sorted(entries.items()):
   info=tarfile.TarInfo('./'+name);info.mode=mode;info.size=len(raw);info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=0;t.addfile(info,io.BytesIO(raw))
 return gzip.compress(stream.getvalue(),mtime=0)
def deb(parts):
 result=b'!<arch>\n'
 for name,raw in parts:
  header=f'{name+"/":<16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(raw):<10}`\n'.encode('ascii');assert len(header)==60
  result+=header+raw+(b'\n' if len(raw)%2 else b'')
 return result
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output-dir',type=pathlib.Path,required=True);args=parser.parse_args()
 root=pathlib.Path(__file__).resolve().parent.parent;target=args.output_dir.resolve()
 if target==root.resolve() or root.resolve() in target.parents:parser.error('Output must be a new directory outside this frozen kit.')
 target.mkdir(exist_ok=False)
 if os.name=='nt':root=pathlib.Path('\\\\?\\'+str(root))
 reports=[]
 for name,filename in [('src','gutochat-candidate-r18.deb')]:
  base=root/name;records=json.loads((base/'FILES.json').read_text(encoding='utf-8'));parts={'payload':{},'debian':{}}
  for record in records:
   path=pathlib.PurePosixPath(record['path']);assert not path.is_absolute() and '..' not in path.parts and path.parts[0] in parts
   p=base.joinpath(*path.parts);assert not p.is_symlink() and p.resolve().is_relative_to(base.resolve())
   raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==record['sha256'];mode=record['mode'];assert type(mode) is int and mode&~0o777==0
   parts[path.parts[0]]['/'.join(path.parts[1:])]=(raw,mode)
  data=deb([('debian-binary',b'2.0\n'),('control.tar.gz',archive(parts['debian'])),('data.tar.gz',archive(parts['payload']))])
  with (target/filename).open('xb') as f:f.write(data)
  reports.append({'filename':filename,'sha256':hashlib.sha256(data).hexdigest(),'installed':False})
 print(json.dumps(reports))
if __name__=='__main__':main()
