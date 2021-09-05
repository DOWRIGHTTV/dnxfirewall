#!/usr/bin/python3

import json
import sys, os

from types import SimpleNamespace
from ipaddress import IPv4Network

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

def load_page():
    firewall_rules = get_and_format_rules()
    return {
        'firewall_rules': firewall_rules,
        'dmz_dnat_rules': System.nat_rules(),
        'local_snat_rules': System.nat_rules(nat_type='SRCNAT')
    }

# TODO: fix inconcistent variable names for nat rules
def update_page(form):
    print(form)
    # initial input validation for presence of zone field
    zone = form.get('zone', None)
    if (zone not in valid_sections):
        return INVALID_FORM, 'GLOBAL_ZONE', None

    # action field is not required for some functions, so will not be hard validated
    action = form.get('action', DATA.MISSING)

    # firewall rule will not nat_type specified so None  can be used for identification
    nat_type = form.get('nat_type', None)
    if (nat_type is None):
        error, zone = _firewall_rules(zone, action, form)

    elif (nat_type in ['DSTNAT', 'SRCNAT']):

        if (nat_type == 'DSTNAT'):
            error, zone = _dnat_rules(zone, action, form)

        elif (nat_type == 'SRCNAT'):
            error, zone = _snat_rules(zone, action, form)

    else:
        return INVALID_FORM, zone, None

    # updating page data then returning. this is because we need to serve the content with the newly added
    # configuration item.
    page_data = {
        'netmasks': NETMASKS,
        'firewall_rules': System.firewall_rules(chain=zone),
        'dmz_dnat_rules': System.nat_rules(),
        'local_snat_rules': System.nat_rules(nat_type='SRCNAT')
    }

    # print(f'RETURNING: {page_data}')
    return error, zone, page_data

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

# TODO: currently it is possible to put overlapping DNAT rules (same dst port, but different host port).
    # this isnt normally an issue and could be left to the user, but the last one inserted with be
    # the local port value, which if the lower rule, will be incorrect for portscan reject packets.
    # a similar issue will also be for the local ports because they are flipped when loaded into the
    # ips.
        # NOTE: a possible solution would be to store the wan ip/wan port and local ip/ local port in a tuple
        # or a splittable string. this could be the key/vals to the dict making each unique and would allow
        # for any combination and still properly identify missed scans while also reliable generating reject
        # packets.
def _dnat_rules(zone, action, form):
    error = None

    fields = SimpleNamespace(**form)
    if (action == 'remove'):
        try:
            # NOTE: validation needs to know the zone so it can ensure the position is valid
            validate.del_nat_rule(fields)
        except ValidationError as ve:
            error = ve

        else:
            with IPTablesManager() as iptables:
                iptables.delete_nat(fields)

                configure.del_open_wan_protocol(fields)

    elif (action == 'add'):
        try:
            # checking all required fields are present and some other basic rules are followed
            # before validating values of standard fields.
            validate.add_dnat_rule(fields)

            if (fields.protocol in ['tcp', 'udp']):
                validate.network_port(fields.dst_port)
                validate.network_port(fields.host_port)

            validate.ip_address(fields.host_ip)

            if (fields.dst_ip != ''):
                validate.ip_address(fields.dst_ip)

        except ValidationError as ve:
            error = ve
        else:
            with IPTablesManager() as iptables:
                iptables.add_nat(fields)

                configure.add_open_wan_protocol(fields)

    else:
        return INVALID_FORM, zone

    return error, zone

def _snat_rules(zone, action, form):
    error = None

    fields = SimpleNamespace(**form)
    # TODO: make this code for snat (currently using dnat code as template)
    if (action == 'remove'):
        try:
            # NOTE: validation needs to know the zone so it can ensure the position is valid
            validate.del_nat_rule(fields)
        except ValidationError as ve:
            error = ve

        else:
            with IPTablesManager() as iptables:
                iptables.delete_nat(fields)

    elif (action == 'add'):
        try:
            validate.add_snat_rule(fields)

            validate.ip_address(ip_iter=[fields.orig_src_ip, fields.new_src_ip])

        except ValidationError as ve:
            error = ve
        else:
            with IPTablesManager() as iptables:
                iptables.add_nat(fields)

    else:
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