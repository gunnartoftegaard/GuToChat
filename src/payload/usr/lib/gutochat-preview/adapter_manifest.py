"""Pure installer-owned recipe generation. Never opens hardware or applies files.

Inventory must come from the administrator's fresh local observation, not a GUI
proposal. Recipes are reviewed inputs to installation, not activation receipts.
"""
import copy
import hashlib
import json
import pathlib
import re


class CommissionError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise CommissionError(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_device(device):
    require(isinstance(device, dict) and set(device) == {'kind', 'route_key', 'label', 'band', 'usb_id', 'api_port', 'channel_index'}, 'DEVICE_FIELDS_INVALID')
    require(device['kind'] == 'meshtastic_usb', 'ADAPTER_NOT_IMPLEMENTED')
    require(isinstance(device['route_key'], str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}', device['route_key']) and device['route_key'] != 'waveshare', 'ROUTE_INVALID')
    require(isinstance(device['label'], str) and 0 < len(device['label'].strip()) <= 100 and all(ord(c) >= 32 for c in device['label']), 'LABEL_INVALID')
    require(device['band'] in ('868', '433'), 'BAND_INVALID')
    require(isinstance(device['usb_id'], str) and re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', device['usb_id']), 'USB_ID_INVALID')
    require(type(device['api_port']) is int and 1024 <= device['api_port'] <= 65535, 'PORT_INVALID')
    require(type(device['channel_index']) is int and 0 <= device['channel_index'] <= 7, 'CHANNEL_INVALID')


def validate_inventory(observed):
    require(isinstance(observed, dict) and set(observed) == {'stable_path', 'device_number', 'identity_sha256'}, 'INVENTORY_FIELDS_INVALID')
    require(isinstance(observed['stable_path'], str) and re.fullmatch(r'/dev/serial/by-id/[a-zA-Z0-9_.:+-]{1,220}', observed['stable_path']), 'STABLE_USB_ID_REQUIRED')
    require(type(observed['device_number']) is int and observed['device_number'] > 0, 'DEVICE_NUMBER_INVALID')
    require(isinstance(observed['identity_sha256'], str) and re.fullmatch('[0-9a-f]{64}', observed['identity_sha256']), 'USB_IDENTITY_REQUIRED')


def make_recipe(core, registration, registry, devices, inventory, dependencies_ready):
    """Generate disabled adapters; preserve all live core settings verbatim.

    No RX/TX/publishing permission is inferred from registering a USB device.
    Private-radio and SDR requests are rejected until their adapters exist.
    """
    require(isinstance(core, dict) and isinstance(registration, dict) and isinstance(registry, dict), 'INSTALLATION_INVALID')
    require(set(core) == {'role','address','node_name','station_name','ui_language','private_radio_enabled','meshtastic_radios','meshtastic_gateways','api_host','api_port','database','contacts_file','ui_state_file','offline_map_directory','map_aprs_database','map_aprs_live_enabled','map_aprs_headless_enabled','ui_refresh_interval_seconds'}, 'CORE_ONLY_BASELINE_REQUIRED')
    require(core['private_radio_enabled'] is False and core['meshtastic_gateways'] == [] and core['api_host'] == '127.0.0.1', 'CORE_ONLY_BASELINE_REQUIRED')
    require(isinstance(dependencies_ready, bool) and dependencies_ready, 'MESHTASTIC_DEPENDENCIES_REQUIRED')
    require(set(registration) == {'schema_version', 'selection', 'units'} and registration['schema_version'] == 1, 'REGISTRATION_INVALID')
    selection = registration['selection']
    require(isinstance(selection, dict) and set(selection) == {'role', 'language', 'username', 'groupname', 'uid', 'gid'}, 'ACCOUNT_FIELDS_INVALID')
    role = selection['role']
    require(role in ('base', 'field') and core.get('role') == role, 'ROLE_MISMATCH')
    require(selection['language'] in ('nb', 'en') and core.get('ui_language') == selection['language'], 'LANGUAGE_MISMATCH')
    for name in ('username', 'groupname'):
        require(isinstance(selection[name], str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', selection[name]), 'ACCOUNT_INVALID')
    require(type(selection['uid']) is int and selection['uid'] >= 1000 and type(selection['gid']) is int and selection['gid'] > 0, 'ORDINARY_ACCOUNT_REQUIRED')
    cfgroot = '/etc/gutochat-preview/' + role
    data = '/var/lib/gutochat-preview/data/' + role
    require(core.get('database') == data + '/core.sqlite', 'DATABASE_NAMESPACE_INVALID')
    expected = {'schema_version': 1, 'allowed_uid': selection['uid'], 'allowed_gid': selection['gid'], 'config_root': cfgroot, 'backup_root': '/var/lib/gutochat-preview/broker/'+role+'/backups', 'core_file': 'config.json', 'core_unit': 'gutochat-preview-'+role+'-core.service'}
    require(set(registry) == set(expected) | {'bindings', 'bound_files', 'aprs'}, 'REGISTRY_FIELDS_INVALID')
    require(all(registry.get(k) == v for k, v in expected.items()), 'REGISTRY_NAMESPACE_INVALID')
    require(registry['bound_files'] == [] and registry['aprs'] is None, 'PUBLICATION_BINDING_REQUIRES_SEPARATE_TRANSACTION')
    require(registry['bindings'] == {} and core.get('meshtastic_radios') == [], 'EXISTING_ADAPTER_REQUIRES_MIGRATION')
    require(isinstance(devices, list) and 1 <= len(devices) <= 16 and isinstance(inventory, dict), 'DEVICE_LIST_INVALID')
    ports = {core.get('api_port')}
    require(type(core.get('api_port')) is int and 1024 <= core['api_port'] <= 65535, 'CORE_PORT_INVALID')
    keys, paths, identities, numbers = set(), set(), set(), set()
    configs, units, bindings, facts = {}, {}, {}, {}
    for item in devices:
        validate_device(item)
        key = item['route_key']
        require(item['usb_id'] in inventory, 'USB_NOT_OBSERVED')
        observed = inventory[item['usb_id']]
        validate_inventory(observed)
        require(key not in keys and item['api_port'] not in ports, 'DUPLICATE_ROUTE_OR_PORT')
        require(observed['stable_path'] not in paths and observed['identity_sha256'] not in identities and observed['device_number'] not in numbers, 'DUPLICATE_PHYSICAL_DEVICE')
        keys.add(key);ports.add(item['api_port']);paths.add(observed['stable_path']);identities.add(observed['identity_sha256']);numbers.add(observed['device_number'])
        filename = 'mesh-'+key+'.json'
        unit = 'gutochat-preview-'+role+'-mesh-'+key+'.service'
        capability = 'meshtastic_local_'+item['band']
        config = copy.deepcopy(core)
        config['optional_adapter'] = {'schema_version': 1, 'band': item['band'], 'identity_sha256': observed['identity_sha256']}
        config.update(field_base_parity_enabled=False, aprs_field_sync_enabled=False, remote_base_control_enabled=False, remote_base_status_enabled=False)
        config['meshtastic'] = {'route_key': key, 'serial_port': observed['stable_path'], 'api_host': '127.0.0.1', 'api_port': item['api_port'], 'channel_index': item['channel_index'], 'network_name': item['label'], 'capability': capability, 'structured_gateway': False, 'forward_inbound_to': None, 'cursor_key': 'module-'+key, 'uid_prefix': 'module-'+key, 'forward_tag': 'MT'}
        # Enabled publication in an existing core must never be silently cleared.
        require(not any(core.get(k, False) for k in ('map_aprs_live_enabled', 'map_aprs_headless_enabled')), 'PUBLICATION_CHANGE_REQUIRES_REVIEW')
        configs[filename] = config
        units[unit] = (
            '[Unit]\nDescription=GuToChat optional Meshtastic adapter\nAfter='+expected['core_unit']+'\nRequires='+expected['core_unit']+'\n'
            '[Service]\nType=simple\nUser='+selection['username']+'\nGroup='+selection['groupname']+'\nSupplementaryGroups=dialout\n'
            'ExecStart=/usr/bin/python3 -I /usr/lib/gutochat-preview/adapter_entry.py '+role+' '+key+'\n'
            'NoNewPrivileges=yes\nProtectHome=yes\nProtectSystem=strict\nPrivateDevices=no\nDevicePolicy=closed\nDeviceAllow='+observed['stable_path']+' rw\n'
            'ReadWritePaths='+data+'\nRestrictAddressFamilies=AF_UNIX AF_INET\nIPAddressDeny=any\nIPAddressAllow=127.0.0.1/32\nRestart=on-failure\nRestartSec=3\n[Install]\nWantedBy=multi-user.target\n'
        )
        bindings[key] = {'unit': unit, 'config_file': filename, 'serial_port': observed['stable_path'], 'capability': capability}
        facts[item['usb_id']] = copy.deepcopy(observed)
    updated = copy.deepcopy(registry);updated['bindings'] = bindings
    return {'schema_version': 1, 'state': 'COMMISSION_RECIPE_NOT_APPLIED', 'role': role, 'devices':copy.deepcopy(devices), 'baseline_sha256': digest({'core': core, 'registration': registration, 'registry': registry}), 'inventory_sha256': digest(facts), 'inventory': facts, 'configs': configs, 'units': units, 'registry': updated, 'activation': 'SEPARATE_EXPLICIT_STEP', 'publication': 'UNCHANGED_NO_NEW_AUTHORIZATION', 'required_checks': ['fresh_baseline_and_inventory', 'supported_driver_and_firmware', 'protected_code_and_paths', 'unit_registration_update', 'lifecycle_resume_remove_integration', 'backup_journal_and_rollback', 'local_api_and_radio_health']}


def revalidate(recipe, core, registration, registry, inventory, dependencies_ready):
    require(recipe['state'] == 'COMMISSION_RECIPE_NOT_APPLIED', 'RECIPE_STATE_INVALID')
    require(recipe['baseline_sha256'] == digest({'core': core, 'registration': registration, 'registry': registry}), 'BASELINE_CHANGED')
    fresh = {key: inventory.get(key) for key in recipe['inventory']}
    require(digest(fresh) == recipe['inventory_sha256'], 'USB_CHANGED')
    require(make_recipe(core, registration, registry, recipe['devices'], inventory, dependencies_ready) == recipe, 'RECIPE_CHANGED')
