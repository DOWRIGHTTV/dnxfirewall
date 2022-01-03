#!/usr/bin/python3

import csv

from types import SimpleNamespace
from ipaddress import IPv4Network
from collections import defaultdict

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

    firewall_objects = load_temporary_objects()

    fw_obj_dict = {int(x[0]): x[1:] for x in firewall_objects}

    firewall_rules = get_and_format_rules(section, fw_obj_dict)

    return {
        'zone_map': zone_map,
        'zone_manager': zone_manager,
        'firewall_objects': firewall_objects,
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

def get_and_format_rules(section, fw_obj_dict, version='pending'):
    proto_map = {0: 'any', 1: 'icmp', 6: 'tcp', 17: 'udp'}

    firewall_rules = FirewallManage.cfirewall.view_ruleset(section, version)

    converted_rules = []
    converted_rules_append = converted_rules.append

    zone_map_get = _zone_map.get
    obj_get = fw_obj_dict.get

    # convert rules into a friendly format
    for rule in firewall_rules.values():

        # print(rule)

        # "2": [1, 0, 4294967295, 32, 65537, 65535, 0, 4294967295, 32, 131071, 65535, 1, 0, 0, 0],
        src_zone = zone_map_get(rule['src_zone'][0], 'ERROR')
        dst_zone = zone_map_get(rule['dst_zone'][0], 'ERROR')

        # counting amount of times a zone is seen in a rule. default dict protects new zones ints.
        reference_counts[src_zone] += 1
        reference_counts[dst_zone] += 1

        t_rule = [
            rule['enabled'], rule['name'],

            src_zone,
            [obj_get(x) for x in rule['src_network']], [obj_get(x) for x in rule['src_service']],

            dst_zone,
            [obj_get(x) for x in rule['dst_network']], [obj_get(x) for x in rule['dst_service']],

            rule['action'], rule['log'],
            rule['ipp_profile'], rule['ips_profile']
        ]

        # # error is for initial testing period to make it easier to detect if zone manager and
        # # firewall rules get desynced.
        # rule[1] = _zone_map.get(rule[1], 'ERROR')
        # rule[6] = _zone_map.get(rule[6], 'ERROR')
        #
        # rule[11] = 'accept' if rule[11] else 'deny' # this could probably get removed since 0/1 is ok for this.
        # rule[12] = 'Y' if rule[12] else 'N'
        #
        # # merging ip/netmask and converting > ip address > str
        # rule[2] = f'{IPv4Network((rule[2], rule[3]))}'
        # rule[7] = f'{IPv4Network((rule[7], rule[8]))}'
        #
        # # src and dst port conversion
        # for i in [4, 9]:
        #
        #     proto = rule[i] >> 16
        #     p_1 = rule[i] & 65535
        #     p_2 = rule[i+1] & 65535
        #
        #     rule[i] = f'{proto_map[proto]}/{p_1}'
        #     if (p_1 < p_2):
        #         rule[i] += f'-{p_2}'
        #
        # # removing fields for items that were merged into another field
        # cv_rule = [x for i, x in enumerate(rule) if i not in [3, 5, 8, 10]]

        print(t_rule)

        converted_rules_append(t_rule)

    return converted_rules

def is_pending_changes():
    active = calculate_file_hash('firewall_active.json', folder='iptables/usr')
    pending = calculate_file_hash('firewall_pending.json', folder='iptables/usr')

    # if user has never modified rules, there is no pending changes. active file can be none
    # if pending is present since a commit will write the active file.
    if (pending is None):
        return False

    return active != pending

def load_temporary_objects():
    with open(f'{HOME_DIR}/dnx_webui/data/builtin_fw_objects.csv') as fw_objects:
        object_list = [x for x in csv.reader(fw_objects) if x and '#' not in x[0]]

    # slicing out keys
    return object_list[1:]
