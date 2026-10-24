"""Ordinary-user core entry; no imports from a working directory."""
import os,pathlib,sys
CODE=pathlib.Path('/usr/lib/gutochat-preview')
if os.geteuid()==0 or len(sys.argv)!=2 or sys.argv[1] not in ('base','field'):
    raise SystemExit('ORDINARY_USER_AND_ROLE_REQUIRED')
role=sys.argv[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(CODE/'app'/role.upper()))
sys.argv=['lorad','--config','/etc/gutochat-preview/'+role+'/config.json']
import lorad
raise SystemExit(lorad.main())
