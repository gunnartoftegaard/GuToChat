"""Only public GUI selection fields; never expose USB IDs, paths or secrets."""
from adapter_manifest import require


def catalog(bindings,configs):
    result=[]
    for route,binding in sorted(bindings.items()):
        require(binding['config_file']=='mesh-'+route+'.json','CATALOG_BINDING_INVALID')
        mesh=configs[binding['config_file']]['meshtastic']
        require(mesh['route_key']==route and mesh['serial_port']==binding['serial_port'],'CATALOG_IDENTITY_INVALID')
        item={'route_key':route,'label':mesh['network_name'],'enabled':False,'api_host':'127.0.0.1','api_port':mesh['api_port'],'channel_index':mesh['channel_index']}
        result.append(item)
    from device_setup import validate_selection
    # The caller checks the actual core port as well before emitting a proposal.
    validate_selection({'private_radio_enabled':False,'meshtastic_radios':result},0)
    return result


def merge_registered(current,registered):
    """Keep actual current choices; add registered-but-unselected devices disabled."""
    import copy
    selection=copy.deepcopy(current)
    known={item['route_key'] for item in selection['meshtastic_radios']}
    for item in registered:
        if item['route_key'] not in known:
            new=copy.deepcopy(item);new['enabled']=False
            selection['meshtastic_radios'].append(new);known.add(item['route_key'])
    return selection
