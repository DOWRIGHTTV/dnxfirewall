#!/usr/bin/python3

from collections import defaultdict
from flask import Flask, jsonify

import dnx_routines.configure.web_validate as validate

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.file_operations import load_configuration
from dnx_routines.configure.exceptions import ValidationError

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

def load_page(section='MAIN'):
    global _zone_map

    dnx_settings = load_configuration('config')

    dnx_intfs = dnx_settings['interfaces']
    dnx_zones = dnx_settings['zones']

    # building out interface to zone map NOTE: builtins only for now
    for intf_type in ['builtins', 'extended']:
        for intf_name, intf_info in dnx_intfs[intf_type].items():
            ident = intf_info['ident']

            zone_map[intf_type][ident] = intf_name

    # building zone list and reference counts NOTE: builtins only for now
    for zone_type in ['builtins', 'user-defined']:
        for zone_name, (zone_ident, zone_desc) in dnx_zones[zone_type].items():

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

def update_page(form):

    # initial input validation for presence of zone field
    section = form.get('section', None)
    if (section not in valid_sections or 'change_section' not in form):
        return INVALID_FORM, 'MAIN', load_page(section)

    return None, section, load_page(section)

def get_and_format_rules(section):
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

        t_rule = [
            rule['enabled'], rule['name'],

            src_zone,
            [obj_lookup(x) for x in rule['src_network']], [obj_lookup(x) for x in rule['src_service']],

            dst_zone,
            [obj_lookup(x) for x in rule['dst_network']], [obj_lookup(x) for x in rule['dst_service']],

            rule['action'], rule['log'],
            rule['ipp_profile'], rule['ips_profile']
        ]

        converted_rules_append(t_rule)

    return converted_rules

def commit_rules(json_data):

    if not json_data.get('section', None):
        return False, {'error': True, 'message': 'missing section data'}

    if not json_data.get('rules', None):
        return False, {'error': True, 'message': 'missing rule data'}

    # NOTE: all rules must be validated for any changes to be applied. validation will raise exception on first error.
    try:
        validated_rules = validate.firewall_commit(json_data['rules'])
    except ValidationError as ve:
        return False, {'error': True, 'message': str(ve)}

    else:
        FirewallManage.commit(validated_rules)

    return True, {'error': False, 'message': None}
