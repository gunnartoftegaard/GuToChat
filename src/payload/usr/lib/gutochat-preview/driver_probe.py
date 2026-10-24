"""Optional dependency probe; imports run only as the ordinary account."""
import os,pathlib,sys
sys.dont_write_bytecode=True
if os.name!='posix' or os.geteuid()==0:raise SystemExit('ORDINARY_ACCOUNT_REQUIRED')
root=pathlib.Path('/usr/lib/gutochat-meshtastic-driver/python')
sys.path.insert(0,str(root))
import meshtastic.serial_interface,serial,pubsub,yaml,google.protobuf,requests
print('MESHTASTIC_DRIVER_READY')
