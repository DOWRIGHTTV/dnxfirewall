#!/usr/bin/python3

import csv

from types import SimpleNamespace
from collections import defaultdict
from flask import Flask, jsonify

import dnx_routines.configure.web_validate as validate

from dnx_gentools.def_constants import HOME_DIR, INVALID_FORM
from dnx_gentools.file_operations import load_configuration, calculate_file_hash
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
        'pending_changes': is_pending_changes()
    }

def update_page(form):
    print(form)

    error = None

    # initial input validation for presence of zone field
    section = form.get('section', None)
    if (section not in valid_sections):
        return INVALID_FORM, 'MAIN', load_page(section)

    elif ('create_rule' in form):
        fw_rule = SimpleNamespace(**form)

        fw_rule.src_network = form.getlist('src_network')
        fw_rule.src_service = form.getlist('src_service')
        fw_rule.dst_network = form.getlist('dst_network')
        fw_rule.dst_service = form.getlist('dst_service')

        try:
            converted_rule = validate.manage_firewall_rule(fw_rule)
        except ValidationError as ve:
            error = ve

        else:
            FirewallManage.cfirewall.add(fw_rule.position, converted_rule, section=section)

    elif ('modify_rule' in form):
        # return 'Rule modification is currently disabled.', section, load_page(section)

        fw_rule = SimpleNamespace(**form)
        try:
            converted_rule = validate.manage_firewall_rule(fw_rule)
        except ValidationError as ve:
            error = ve

        else:
            FirewallManage.cfirewall.modify(fw_rule.static_pos, fw_rule.position, converted_rule, section=section)

    elif ('remove_rule' in form):
        pos = form.get('position', None)
        if (not pos):
            return INVALID_FORM, section, load_page(section)

        FirewallManage.cfirewall.remove(pos, section=section)

    elif ('commit_rules' in form):
        FirewallManage.cfirewall.commit()

    elif ('revert_rules' in form):
        FirewallManage.cfirewall.revert()

    # functional else minus change section request.
    elif ('change_section' not in form):
        return INVALID_FORM, 'MAIN', load_page(section)

    return error, section, load_page(section)

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

        print(t_rule)

        converted_rules_append(t_rule)

    return converted_rules

# TODO: move this to firewall manager
def is_pending_changes():
    active = calculate_file_hash('firewall_active.json', folder='iptables/usr')
    pending = calculate_file_hash('firewall_pending.json', folder='iptables/usr')

    # if user has never modified rules, there is no pending changes. active file can be none
    # if pending is present since a commit will write the active file.
    if (pending is None):
        return False

    return active != pending
