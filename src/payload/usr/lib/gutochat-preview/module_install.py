"""Transaction for registering disabled adapters, with bounded rollback.

The root entry must supply a protected store, fresh USB observer and dependency
probe. This registers modules only; it never starts a radio adapter.
"""
import copy
import hashlib
import json
from adapter_manifest import revalidate, require, digest


def encoded(value):return (json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()


def commission(recipe,store,services,observe_inventory,dependencies_ready):
    """Store API owns protected paths/locking/backups; names remain recipe-bound.

    Caller holds the package administrator lock and ensures GUI exit. Services
    exposes only the fixed role broker. No service name is accepted from GUI.
    """
    original_core=store.read('config','config.json')
    core=json.loads(original_core['raw'])
    registration=json.loads(store.read('config','installation.json')['raw'])
    registry=json.loads(store.read('config','registry.json')['raw'])
    revalidate(recipe,core,registration,registry,observe_inventory(),dependencies_ready())
    expected_units={'gutochat-preview-'+recipe['role']+'-'+kind+'.service' for kind in ('core','broker')}
    require(set(registration['units'])==expected_units,'CORE_UNIT_REGISTRATION_INVALID')
    for name,want in registration['units'].items():
        existing=store.read('unit',name)
        require(existing is not None and sha(existing['raw'])==want,'CORE_UNIT_CHANGED')
    require(store.read('config','module_registration.json') is None,'MODULES_ALREADY_REGISTERED')
    registration_after=copy.deepcopy(registration)
    registration_after['units'].update({name:sha(text.encode()) for name,text in recipe['units'].items()})
    proposed={('config',name):{'raw':encoded(cfg),'mode':0o640,'gid':registration['selection']['gid']} for name,cfg in recipe['configs'].items()}
    proposed.update({('unit',name):{'raw':text.encode(),'mode':0o644,'gid':0} for name,text in recipe['units'].items()})
    proposed[('config','module_registration.json')]={'raw':encoded({'schema_version':1,'devices':recipe['devices'],'inventory':recipe['inventory']}),'mode':0o600,'gid':0}
    for key in proposed:require(store.read(*key) is None,'ADAPTER_FILE_ALREADY_EXISTS')
    for name,value in (('registry.json',recipe['registry']),('installation.json',registration_after)):
        proposed[('config',name)]={'raw':encoded(value),'mode':0o600,'gid':0}
    before={key:store.read(*key) for key in proposed}
    broker=services.snapshot_broker()
    require(broker['active'] is True,'BROKER_MUST_BE_RUNNING')
    # Backup interface must persist bytes/metadata and hashes before any change.
    store.backup(before)
    record={'state':'BACKED_UP','baseline_sha256':recipe['baseline_sha256'],'inventory_sha256':recipe['inventory_sha256'],'files':[{'space':space,'name':name,'old_sha256':sha(before[(space,name)]['raw']) if before[(space,name)] else None,'new_sha256':sha(meta['raw'])} for (space,name),meta in proposed.items()]}
    store.journal(record)
    written=[]
    try:
        services.stop_broker()
        fresh_core=json.loads(store.read('config','config.json')['raw'])
        fresh_manifest=json.loads(store.read('config','installation.json')['raw'])
        fresh_registry=json.loads(store.read('config','registry.json')['raw'])
        revalidate(recipe,fresh_core,fresh_manifest,fresh_registry,observe_inventory(),dependencies_ready())
        record['state']='WRITING';store.journal(record)
        for key,meta in proposed.items():
            # Store atomically compares the current state with the expected old state.
            written.append(key);store.write(*key,meta=meta,expected=before[key])
        services.reload()
        # Units are newly registered, not selected or enabled; reject external activation.
        for name in recipe['units']:require(services.adapter_inactive_disabled(name),'ADAPTER_ACTIVATED_EXTERNALLY')
        services.start_broker()
        require(services.broker_healthy(),'BROKER_HEALTH_CHECK_FAILED')
        for key,meta in proposed.items():require(store.read(*key)==meta,'INSTALL_POSTCHECK_FAILED')
        require(store.read('config','config.json')==original_core,'CORE_CHANGED_DURING_COMMISSION')
        record['state']='COMPLETE_DISABLED';store.journal(record)
        return {'state':'COMPLETE_DISABLED','role':recipe['role'],'registered_routes':sorted(recipe['registry']['bindings']),'publication':'UNCHANGED','activation':'NOT_STARTED'}
    except Exception:
        record['state']='ROLLING_BACK';store.journal(record)
        try:
            services.stop_broker()
            for key in reversed(written):
                current=store.read(*key)
                if current==before[key]:continue
                require(current==proposed[key],'EXTERNAL_CHANGE_REQUIRES_REVIEW')
                if before[key] is None:store.remove(*key,expected=proposed[key])
                else:store.write(*key,meta=before[key],expected=proposed[key])
            services.reload()
            if broker['active']:services.start_broker()
            require(services.broker_healthy(),'ROLLBACK_BROKER_HEALTH_FAILED')
            for key,meta in before.items():require(store.read(*key)==meta,'ROLLBACK_POSTCHECK_FAILED')
            record['state']='ROLLED_BACK';store.journal(record)
            return {'state':'ROLLED_BACK','role':recipe['role'],'activation':'NOT_STARTED'}
        except Exception:
            record['state']='ROLLBACK_FAILED_REVIEW_REQUIRED';store.journal(record)
            store.block_new_operations()
            raise
