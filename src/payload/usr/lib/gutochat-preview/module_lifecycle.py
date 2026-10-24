"""Validate registered optional modules and derive bounded lifecycle templates.

All inputs are administrator-owned records. This module does not start services.
"""
import copy
import hashlib
from adapter_manifest import make_recipe, CommissionError, require


def templates(selection, core, registry, modules, layout):
    basic=layout.configuration(selection,core.get('api_port'))
    radios=copy.deepcopy(core.get('meshtastic_radios'))
    reduced=copy.deepcopy(core);reduced['meshtastic_radios']=[]
    require(reduced==basic,'UNREGISTERED_CORE_CONFIGURATION')
    core_units=layout.units(selection)
    if modules is None:
        require(radios==[] and registry==layout.registry(selection),'MODULE_REGISTRATION_REQUIRED')
        return core_units
    require(isinstance(modules,dict) and set(modules)=={'schema_version','devices','inventory'} and modules['schema_version']==1,'MODULE_REGISTRATION_INVALID')
    manifest={'schema_version':1,'selection':selection,'units':{n:hashlib.sha256(b).hexdigest() for n,b in core_units.items()}}
    recipe=make_recipe(basic,manifest,layout.registry(selection),modules['devices'],modules['inventory'],True)
    require(registry==recipe['registry'],'MODULE_REGISTRY_CHANGED')
    from device_setup import validate_selection
    cleaned=[]
    for item in radios:
        require(isinstance(item,dict) and set(item)=={'route_key','label','enabled','api_host','api_port','channel_index','capability'},'MODULE_SELECTION_INVALID')
        key=item['route_key'];require(key in registry['bindings'],'ADAPTER_NOT_REGISTERED')
        require(item['capability']==registry['bindings'][key]['capability'],'MODULE_CAPABILITY_CHANGED')
        cleaned.append({k:v for k,v in item.items() if k!='capability'})
    validate_selection({'private_radio_enabled':False,'meshtastic_radios':cleaned},core['api_port'])
    return {**core_units,**{name:text.encode() for name,text in recipe['units'].items()}}


def enabled_units(core,registry,layout):
    result={name:True for name in layout.unit_names(core['role'])}
    selected={item['route_key']:item['enabled'] for item in core['meshtastic_radios']}
    result.update({binding['unit']:bool(selected.get(key,False)) for key,binding in registry['bindings'].items()})
    return result


def validate_adapter_configs(core,selection,registry,modules,configs,layout):
    templates(selection,core,registry,modules,layout)
    if modules is None:
        require(configs=={},'UNREGISTERED_ADAPTER_FILES');return
    basic=layout.configuration(selection,core['api_port'])
    manifest={'schema_version':1,'selection':selection,'units':{}}
    recipe=make_recipe(basic,manifest,layout.registry(selection),modules['devices'],modules['inventory'],True)
    require(set(configs)==set(recipe['configs']),'ADAPTER_CONFIG_SET_CHANGED')
    selected={item['route_key']:item for item in core['meshtastic_radios']}
    for name,expected in recipe['configs'].items():
        cfg=configs[name];require(isinstance(cfg,dict) and isinstance(cfg.get('meshtastic'),dict),'ADAPTER_CONFIG_INVALID')
        actual=copy.deepcopy(cfg)
        mesh=actual['meshtastic'];key=mesh.get('route_key')
        require(key in registry['bindings'],'ADAPTER_CONFIG_IDENTITY_CHANGED')
        for field in ('api_port','channel_index'):
            value=mesh.get(field)
            require(type(value) is int and (1024<=value<=65535 if field=='api_port' else 0<=value<=7),'ADAPTER_ENDPOINT_INVALID')
            if key in selected:require(value==selected[key][field],'ADAPTER_ENDPOINT_MISMATCH')
            mesh[field]=expected['meshtastic'][field]
        require(actual==expected,'UNREGISTERED_ADAPTER_CONFIGURATION')
