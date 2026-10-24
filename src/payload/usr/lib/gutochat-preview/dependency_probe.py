"""Read-only prerequisites for the Linux core-only installer pilot."""
import importlib,importlib.util,json,os,pathlib,shutil,socket,sys

def check():
    checks={'linux':sys.platform=='linux','python_3_11_or_newer':sys.version_info[:2]>=(3,11),
            'systemd_running':pathlib.Path('/run/systemd/system').is_dir(),
            'systemctl':bool(shutil.which('systemctl')),
            'linux_peer_identity':hasattr(socket,'SO_PEERCRED') and hasattr(os,'pidfd_open')}
    for module,key in [('sqlite3','sqlite'),('tkinter','tk'),('PIL.Image','pillow'),('PIL.ImageTk','imagetk')]:
        try:importlib.import_module(module);checks[key]=True
        except (ImportError,OSError):checks[key]=False
    return {'schema_version':1,'ready':all(checks.values()),'checks':checks,
            'missing':[k for k,v in checks.items() if not v],
            'desktop_authentication_available':bool(shutil.which('pkexec')),
            'desktop_validator_available':bool(shutil.which('desktop-file-validate')),
            'radio_drivers_required':False,'packages_installed_by_check':False}

if __name__=='__main__':
    result=check();print(json.dumps(result,indent=2));raise SystemExit(0 if result['ready'] else 1)
