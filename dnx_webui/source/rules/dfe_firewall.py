#!/usr/bin/python3

import json

from typing import Optional, Any

from collections import defaultdict, namedtuple
from flask import Flask

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.file_operations import load_configuration
from dnx_routines.configure.web_validate import ValidationError, convert_int

from dnx_secmods.cfirewall.fw_manage import FirewallManage

valid_sections = {
    'BEFORE': '1',
    'MAIN': '2',
    'AFTER': '3',
}

reference_counts = defaultdict(int)
zone_map = {'builtins': {}, 'extended': {}}
zone_manager = {'builtins': {}, 'user-defined': {}}

# including 0/any since it is not an actual zone definition
_zone_map = {99: 'any'}

def load_page(section: str = 'MAIN') -> dict[str, Any]:
    global _zone_map

    dnx_settings = load_configuration('system')

    # building out interface to zone map NOTE: builtins only for now
    for intf_type in ['builtins', 'extended']:
        for intf_name, intf_info in dnx_settings.get_items(f'interfaces->{intf_type}'):
            ident = intf_info['ident']

            zone_map[intf_type][ident] = intf_name

    # building zone list and reference counts NOTE: builtins only for now
    for zone_type in ['builtins', 'user-defined']:
        for zone_name, (zone_ident, zone_desc) in dnx_settings.get_items(f'zones->{zone_type}'):

            # need to make converting zone ident/int to name easier in format function
            _zone_map[zone_ident] = zone_name

            zone_manager[zone_type][zone_name] = [reference_counts[zone_ident], zone_desc]

    version, firewall_objects = Flask.app.dnx_object_manager.get_objects()

    fw_object_map = {obj.name: {'type': obj.type, 'id': obj.id} for obj in firewall_objects}

    network_autofill = {k.name: None for k in firewall_objects if k.type in ['country', 'address']}
    service_autofill = {k.name: None for k in firewall_objects if k.type in ['service']}

    firewall_rules = get_and_format_rules(section)

    return {
        'zone_map': zone_map,
        'zone_manager': zone_manager,
        'firewall_objects': firewall_objects,
        'fw_object_map': fw_object_map,
        'network_autofill': network_autofill,
        'service_autofill': service_autofill,
        'firewall_rules': firewall_rules,
        'pending_changes': FirewallManage.is_pending_changes()
    }

def update_page(form: dict) -> tuple[Optional[str], str]:

    # initial input validation for presence of zone field
    section = form.get('section', None)
    if (section not in valid_sections or 'change_section' not in form):
        return INVALID_FORM, 'MAIN'

    return None, section

def get_and_format_rules(section: str) -> list[Optional[list]]:
    firewall_rules = FirewallManage.cfirewall.view_ruleset(section)

    converted_rules = []
    converted_rules_append = converted_rules.append

    zone_map_get = _zone_map.get
    obj_lookup = Flask.app.dnx_object_manager.lookup

    # convert rules into a friendly format
    for rule in firewall_rules.values():

        src_zone = zone_map_get(rule['src_zone'][0], 'ERROR')
        dst_zone = zone_map_get(rule['dst_zone'][0], 'ERROR')

        # counting amount of times a zone is seen in a rule. default dict protects new zones ints.
        reference_counts[src_zone] += 1
        reference_counts[dst_zone] += 1

        converted_rules_append([
            rule['enabled'], rule['name'],

            src_zone,
            [obj_lookup(x) for x in rule['src_network']], [obj_lookup(x) for x in rule['src_service']],

            dst_zone,
            [obj_lookup(x) for x in rule['dst_network']], [obj_lookup(x) for x in rule['dst_service']],

            rule['action'], rule['log'],
            rule['ipp_profile'], rule['dns_profile'], rule['ips_profile']
        ])

    return converted_rules

def commit_rules(json_data):

    section = json_data.get('section', None)
    if (not section or section not in valid_sections):
        return False, {'error': True, 'message': 'missing section data'}

    if not json_data.get('rules', None):
        return False, {'error': True, 'message': 'missing rule data'}

    # NOTE: all rules must be validated for any changes to be applied. validation will raise exception on first error.
    try:
        validated_rules = {section: validate_firewall_commit(json_data['rules'])}
    except ValidationError as ve:
        return False, {'error': True, 'message': str(ve)}

    else:
        FirewallManage.commit(validated_rules)

    # temporary for testing
    FirewallManage.push()

    return True, {'error': False, 'message': None}


# ================
# VALIDATION
# ================
_rule_structure = namedtuple('rule_structure', [
    'enabled', 'name',
    'src_zone', 'src_network', 'src_service',
    'dst_zone', 'dst_network', 'dst_service',
    'action', 'log',
    'sec1_prof', 'sec2_prof', 'sec3_prof'
])

def validate_firewall_commit(fw_rules, /):
    # ["1", "lan_dhcp_allow", "lan", "tv,lan_network tv,dmz_network", "track_changes,udp_any", "any",
    #  "tv,lan_network tv,dmz_network", "track_changes,udp_67", "ACCEPT", "OFF", "0", "0"]

    fw_rules = json.loads(fw_rules)

    validated_rules = {}

    # index/ enumerate is for providing better feedback if issues are detected.
    for i, rule in enumerate(fw_rules.values(), 1):

        try:
            rule = _rule_structure(*rule)
        except ValueError:  # i think its a value error
            raise ValidationError(f'Format error found in rule #{i}')

        try:
            validated_rules[i] = validate_firewall_rule(i, rule)
        except ValidationError:
            raise

    print(validated_rules)
    return validated_rules

# NOTE: log disabled in form and set here as default for the time being.
def validate_firewall_rule(rule_num, fw_rule, /):

    # FASTER CHECKS FIRST
    if (fw_rule.action not in ['ACCEPT', 'DROP']):
        raise ValidationError(f'{INVALID_FORM} [rule #{rule_num}/action]')

    action = 1 if fw_rule.action == 'ACCEPT' else 0

    ip_proxy_profile = convert_int(fw_rule.sec1_prof)
    ips_ids_profile  = convert_int(fw_rule.sec2_prof)
    if not all([x in [0, 1] for x in [ip_proxy_profile, ips_ids_profile]]):
        raise ValidationError(f'Invalid security profile for rule #{rule_num}.')

    enabled = convert_int(fw_rule.enabled)

    # OBJECT VALIDATIONS
    check = Flask.app.dnx_object_manager.iter_validate

    src_network = check(fw_rule.src_network)
    if (None in src_network):
        raise ValidationError(f'A source network object was not found for rule #{rule_num}.')

    src_service = check(fw_rule.src_service)
    if (None in src_service):
        raise ValidationError(f'A source service object was not found for rule #{rule_num}.')

    dst_network = check(fw_rule.dst_network)
    if (None in dst_network):
        raise ValidationError(f'A destination network object was not found for rule #{rule_num}.')

    dst_service = check(fw_rule.src_service)
    if (None in dst_service):
        raise ValidationError(f'A destination service object was not found for rule #{rule_num}.')

    # TODO: make zone map integrated better
    dnx_interfaces = load_configuration('system').get_items('interfaces->builtins')
    lzone_map = {zone_name: zone_info['zone'] for zone_name, zone_info in dnx_interfaces}

    # 99 used to specify wildcard/any zone match
    lzone_map['any'] = 99

    s_zone = zone_map.get(fw_rule.src_zone, None)
    d_zone = zone_map.get(fw_rule.dst_zone, None)
    if (s_zone is None or d_zone is None):
        raise ValidationError(f'{INVALID_FORM} [rule #{rule_num}/zone]')

    rule = {
        'name': fw_rule.name,
        'id': None,
        'enabled': enabled,
        'src_zone': [s_zone],                # [12]
        'src_network': src_network,
        'src_service': src_service,
        'dst_zone': [d_zone],                # [11]
        'dst_network': dst_network,
        'dst_service': dst_service,
        'action': action,                    # 1
        'log': 0,
        'ipp_profile': ip_proxy_profile,
        'ips_profile': ips_ids_profile
    }

    return rule