"""Read local USB identity metadata only; never open serial ports or radios."""
import hashlib
import json
import pathlib
import stat
import subprocess
from adapter_manifest import validate_inventory, CommissionError


def observe_path(path):
    path=pathlib.Path(path)
    if not path.is_symlink():raise CommissionError('STABLE_USB_SYMLINK_REQUIRED')
    before=path.stat()
    if not stat.S_ISCHR(before.st_mode):raise CommissionError('SERIAL_CHARACTER_DEVICE_REQUIRED')
    result=subprocess.run(['/usr/bin/udevadm','info','--query=property','--name='+path.as_posix()],capture_output=True,text=True,timeout=5,check=True)
    properties=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    required=('ID_VENDOR_ID','ID_MODEL_ID','ID_SERIAL_SHORT')
    if any(not properties.get(k) for k in required):raise CommissionError('UNIQUE_USB_SERIAL_REQUIRED')
    after=path.stat()
    if (before.st_dev,before.st_ino,before.st_rdev)!=(after.st_dev,after.st_ino,after.st_rdev):raise CommissionError('USB_CHANGED_DURING_OBSERVATION')
    fingerprint=hashlib.sha256(json.dumps({k:properties[k] for k in required},sort_keys=True).encode()).hexdigest()
    observed={'stable_path':path.as_posix(),'device_number':after.st_rdev,'identity_sha256':fingerprint}
    validate_inventory(observed)
    return fingerprint[:24],observed


def inventory():
    root=pathlib.Path('/dev/serial/by-id')
    if not root.exists():return {}
    result={}
    for path in sorted(root.iterdir()):
        key,observed=observe_path(path)
        # Aliases are not presented as different physical radios.
        if key in result:
            if result[key]['device_number']!=observed['device_number']:raise CommissionError('USB_IDENTITY_COLLISION')
            continue
        result[key]=observed
    return result
