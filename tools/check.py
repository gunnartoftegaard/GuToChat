"""Run synthetic tests without installing packages or opening radios."""
import os,pathlib,subprocess,sys
root=pathlib.Path(__file__).resolve().parent.parent
env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1'
code=root/'src/payload/usr/lib/gutochat-preview';env['GUTOCHAT_CANDIDATE_CODE']=str(code)
for name,args in [('test_public_contracts.py',['-v']),('test_ack_registration_race.py',[str(code/'app')]),('test_storage_atomicity.py',[str(code/'app')]),('test_position_upgrade.py',[str(code/'app'),str(root/'tests/historical_position')]),('test_preview_gui_core.py',[str(code/'app')]),('test_mesh_recovery18.py',[str(code/'app')]),('test_database_restore18.py',[str(code/'app'),str(root/'tests/test_mesh_recovery18.py'),str(root/'tests/helpers/backup_tool.py')])]:
    subprocess.run([sys.executable,'-B',str(root/'tests'/name),*args],cwd=root,env=env,check=True)
