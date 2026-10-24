"""Secret-free staged device selections. Never writes live configuration."""
import copy
import json
import pathlib
import re
from module_selection import private_radio_enabled

def selection_from_config(config):
    devices = []
    for item in config.get('meshtastic_radios', []):
        devices.append({
            'route_key': str(item.get('route_key') or item.get('key') or ''),
            'label': str(item.get('label') or item.get('route_key') or ''),
            'enabled': item.get('enabled', True),
            'api_host': str(item.get('api_host', '127.0.0.1')),
            'api_port': item.get('api_port'),
            'channel_index': item.get('channel_index', 0),
        })
    return {'private_radio_enabled': private_radio_enabled(config), 'meshtastic_radios': devices}

def validate_selection(selection, core_port=8765):
    if not isinstance(selection.get('private_radio_enabled'), bool):
        raise ValueError('private_radio_enabled: boolean required')
    devices = selection.get('meshtastic_radios')
    if not isinstance(devices, list):
        raise ValueError('meshtastic_radios: list required')
    keys, endpoints = set(), set()
    for item in devices:
        if not isinstance(item, dict):
            raise ValueError('Invalid device')
        key = item.get('route_key', '')
        if not isinstance(key, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}', key) or key == 'waveshare':
            raise ValueError('route_key: invalid or reserved')
        if key in keys:
            raise ValueError('route_key: duplicate')
        keys.add(key)
        label = item.get('label')
        if not isinstance(label, str) or not label.strip() or len(label) > 100 or any(ord(c) < 32 for c in label):
            raise ValueError('label: required, maximum 100 characters')
        if not isinstance(item.get('enabled'), bool):
            raise ValueError('enabled: boolean required')
        # First installer supports local adapters only; do not turn arbitrary hosts into gateways.
        if item.get('api_host') != '127.0.0.1':
            raise ValueError('api_host: local adapter 127.0.0.1 required')
        port = item.get('api_port')
        if type(port) is not int or not 1024 <= port <= 65535 or port == core_port:
            raise ValueError('api_port: invalid or conflicts with core')
        if port in endpoints:
            raise ValueError('api_port: duplicate')
        endpoints.add(port)
        channel = item.get('channel_index')
        if type(channel) is not int or not 0 <= channel <= 7:
            raise ValueError('channel_index: expected 0–7')
    return copy.deepcopy(selection)

def create_plan(config, selection):
    desired = validate_selection(selection, config.get('api_port', 8765))
    current = selection_from_config(config)
    changes = []
    if current['private_radio_enabled'] != desired['private_radio_enabled']:
        changes.append({'module': 'private_radio', 'enabled': desired['private_radio_enabled']})
    before = {d['route_key']: d for d in current['meshtastic_radios']}
    after = {d['route_key']: d for d in desired['meshtastic_radios']}
    for key in sorted(before.keys() | after.keys()):
        if before.get(key) != after.get(key):
            changes.append({'module': 'meshtastic', 'route_key': key, 'action': 'remove' if key not in after else 'add' if key not in before else 'update'})
    return {'schema_version': 1, 'state': 'DRAFT_NOT_APPLIED', 'role': config.get('role', 'unknown'),
            'baseline': current, 'desired': desired, 'changes': changes,
            'requires': ['fresh_baseline_check', 'supported_hardware_and_stable_usb_mapping',
                         'adapter_configs_and_services', 'private_gateway_dependencies',
                         'profile_validation', 'aprs_binding_validation', 'backup_and_rollback'],
            'publication': 'UNCHANGED_NO_NEW_AUTHORIZATION'}

def save_plan(path, plan):
    """Exclusive creation: never replace a previous proposal."""
    path = pathlib.Path(path)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(plan, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
