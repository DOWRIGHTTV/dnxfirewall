#!/usr/bin/python3

import json
import sys, os

from types import SimpleNamespace
from ipaddress import IPv4Network
from collections import defaultdict

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import INVALID_FORM, DATA
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_iptables import IPTablesManager
from dnx_configure.dnx_system_info import System, Services

from dnx_firewall.fw_control import FirewallManage

valid_sections = {
    'BEFORE': '1',
    'MAIN': '2',
    'AFTER': '3',
}

valid_standard_rule_fields = {
    'position','src_ip','src_netmask','dst_ip','dst_netmask','protocol','dst_port'
}

reference_counts = defaultdict(int)
zone_map = {'builtins': {}, 'extended': {}}
zone_manager = {'builtins': {}, 'user-defined': {}}

def load_page():
    dnx_settings = load_configuration('config')

    dnx_intfs = dnx_settings['interfaces']
    dnx_zones = dnx_settings['zones']

    firewall_rules = get_and_format_rules()

    # building out interface to zone map NOTE: builtins only for now
    for intf_type in ['builtins', 'extended']:
        for intf_name, intf_info in dnx_intfs[intf_type].items():
            ident = intf_info['ident']

            zone_map[intf_type][ident] = intf_name

    # building zone list and reference counts NOTE: builtins only for now
    for zone_type in ['builtins', 'user-defined']:
        for zone_name, (zone_ident, zone_desc) in dnx_zones[zone_type].items():
            zone_manager[zone_type][zone_name] = [reference_counts[zone_ident], zone_desc]

    return {
        'firewall_rules': firewall_rules,
        'zone_map': zone_map,
        'zone_manager': zone_manager
    }

# TODO: fix inconcistent variable names for nat rules
def update_page(form):

    error = None
    # initial input validation for presence of zone field
    section  = form.get('section', None)
    if (section not in valid_sections):
        return INVALID_FORM, 'MAIN', None

    # action field is not required for some functions, so will not be hard validated
    action = form.get('action', DATA.MISSING)

    # firewall rule will not nat_type specified so None  can be used for identification
    # error, zone = _firewall_rules(zone, action, form)

    # else:
    #     return INVALID_FORM, zone, None

    # updating page data then returning. this is because we need to serve the content with the newly added
    # configuration item.
    page_data = {
        'firewall_rules': get_and_format_rules(section=section),
    }

    # print(f'RETURNING: {page_data}')
    return error, section, page_data

def _firewall_rules(zone, action, form):
    error = None
    # moving form data into a simple namespace. this will allow us to validate and mutate it easier
    # than its current state of immutable dict.
    fields = SimpleNamespace(**form)
    if (action == 'remove'):
        try:
            # NOTE: validation needs to know the zone so it can ensure the position is valid
            validate.del_firewall_rule(fields)
        except ValidationError as ve:
            error = ve

        else:
            with IPTablesManager() as iptables:
                iptables.delete_rule(fields)

    elif (action =='add'):
        if not all([x in form for x in valid_standard_rule_fields]):
            return INVALID_FORM, zone

        fields.action = 'ACCEPT' if 'accept' in form else 'DROP'

        try:
            validate.add_firewall_rule(fields)
            if (fields.dst_port):
                validate.network_port(fields.dst_port, port_range=True)

            if (fields.src_ip):
                validate.ip_address(fields.src_ip)
                validate.cidr(fields.src_netmask)

            validate.ip_address(fields.dst_ip)
            validate.cidr(fields.dst_netmask)

        except ValidationError as ve:
            error = ve

        else:
            if (not fields.src_ip):
                fields.src_ip, fields.src_netmask = '0', '0'

            with IPTablesManager() as iptables:
                iptables.add_rule(fields)

    elif ('change_interface' not in form):
        return INVALID_FORM, zone

    return error, zone

def get_and_format_rules(section='MAIN', version='pending'):
    proto_map = {0: 'any', 1: 'icmp', 6: 'tcp', 17: 'udp'}

    firewall_rules = FirewallManage.cfirewall.view_ruleset(section, version)

    converted_rules = []
    converted_rules_append = converted_rules.append

    # convert rules into a friendly format
    for rule in firewall_rules.values():

        #"2": [1, 0, 4294967295, 32, 65537, 65535, 0, 4294967295, 32, 131071, 65535, 1, 0, 0, 0],

        # counting amount of times a zone is seen in a rule. default dict protects new zones ints.
        reference_counts[rule[1]] += 1
        reference_counts[rule[6]] += 1

        rule[1] = rule[1] if rule[1] else 'any'
        # creeped me out.
        if (not rule[6]):
            rule[6] = 'any'

        rule[11] = 'accept' if rule[11] else 'drop'
        rule[12] = 'Y' if rule[12] else 'N'

        rule[13] = rule[13] if rule[13] else ' '
        rule[14] = rule[14] if rule[14] else ' '

        # merging ip/netmask and converting > ip address > str
        rule[2] = f'{IPv4Network((rule[2], rule[3]))}'
        rule[7] = f'{IPv4Network((rule[7], rule[8]))}'

        # src and dst port conversion
        for i in [4, 9]:

            proto = rule[i] >> 16
            p_1   = rule[i] & 65535
            p_2   = rule[i+1] & 65535

            rule[i] = f'{proto_map[proto]}/{p_1}'
            if (p_1 < p_2):
                rule[i] += f'-{p_2}'

        # removing fields for items that were merged into another field
        cv_rule = [x for i, x in enumerate(rule) if i not in [3, 5, 8, 10]]

        converted_rules_append(cv_rule)

    return converted_rules
