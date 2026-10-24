"""Root-owned deployment checks. No user-writable application code as root."""
import json,os,pathlib,stat

class SecurityError(RuntimeError):pass

def protected_path(path,*,directory=False):
    path=pathlib.Path(path)
    if not path.is_absolute():raise SecurityError('ABSOLUTE_PROTECTED_PATH_REQUIRED')
    # lstat every component: resolve() alone would hide symbolic links.
    for component in [*reversed(path.parents),path]:
        metadata=component.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid!=0 or metadata.st_mode&0o022:
            raise SecurityError('ROOT_PROTECTED_PATH_REQUIRED')
        if component!=path and not stat.S_ISDIR(metadata.st_mode):raise SecurityError('PROTECTED_PARENT_INVALID')
    if directory and not stat.S_ISDIR(metadata.st_mode):raise SecurityError('PROTECTED_DIRECTORY_REQUIRED')
    if not directory and not stat.S_ISREG(metadata.st_mode):raise SecurityError('PROTECTED_FILE_REQUIRED')
    return path

def protected_json(path):
    protected_path(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022 or meta.st_size>131072:
            raise SecurityError('PROTECTED_REGISTRY_INVALID')
        with os.fdopen(fd,'r') as stream:
            fd=None;value=json.load(stream)
    finally:
        if fd is not None:os.close(fd)
    if not isinstance(value,dict):raise SecurityError('REGISTRY_OBJECT_REQUIRED')
    return value

def verify_code_tree(root):
    protected_path(root,directory=True)
    for path in pathlib.Path(root).rglob('*'):
        protected_path(path,directory=path.is_dir())

class GuardedEngine:
    def __init__(self,engine,guard):self.engine=engine;self.guard=guard
    def read(self):self.guard();return self.engine.read()
    def prepare(self,plan):self.guard();return self.engine.prepare(plan)
    def fresh(self,receipt):self.guard();return self.engine.fresh(receipt)
    def apply(self,receipt):self.guard();return self.engine.apply(receipt)
