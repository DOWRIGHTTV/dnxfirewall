#!/usr/bin/python3

import json
import sys, os

from types import SimpleNamespace

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import INVALID_FORM
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_iptables import IPTableManager
from dnx_configure.dnx_system_info import System, Services

valid_zones = {
    'GLOBAL_INTERFACE': '1',
    'WAN_INTERFACE': '2',
    'DMZ_INTERFACE': '3',
    'LAN_INTERFACE': '4'
}

zone_convert = {
    '1': 'GLOBAL_INTERFACE',
    '2': 'WAN_INTERFACE',
    '3': 'DMZ_INTERFACE',
    '4': 'LAN_INTERFACE'
}

valid_standard_rule_fields = [
    'position','src_ip','src_netmask','dst_ip','dst_netmask','protocol','dst_port'
]

def load_page():
    return {
        'firewall_rules': System.firewall_rules(),
        'dmz_dnat_rules': System.nat_rules(),
        'local_snat_rules': System.nat_rules(nat_type='SRCNAT'),
        'netmasks': list(reversed(range(24,33)))
    }

# TODO: fix inconcistent variable names for nat rules
def update_page(form):
    # initial input validation for presence of zone field
    zone = form.get('zone', None)
    if (zone not in valid_zones):
        return INVALID_FORM, 'GLOBAL_INTERFACE', None

    # if firewall rule, None will be used for evaluation.
    action = form.get('action', None)
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
    page_data = None
    if not error:
        page_data = {
            'firewall_rules': System.firewall_rules(chain=zone),
            'dmz_dnat_rules': System.nat_rules(),
            'local_snat_rules': System.nat_rules(nat_type='SRCNAT'),
            'netmasks': list(reversed(range(24,33)))
        }

    print(f'RETURNING: {page_data}')

    return error, zone, page_data

def _firewall_rules(zone, action, form):
    error = None
    # moving form data into a simple namespace. this will allow us to validate and mutate it easier
    # that its current state of immutable dict.
    fields = SimpleNamespace(**form)
    if (action == 'remove'):
        try:
            # NOTE: validation needs to know the zone so it can ensure the position is valid
            validate.del_firewall_rule(fields)
        except ValidationError as ve:
            error = ve

        else:
            with IPTableManager() as iptables:
                iptables.delete_rule(fields)

    elif (action =='add'):
        if not all([x in form for x in valid_standard_rule_fields]):
            return INVALID_FORM, zone

        fields.action = 'ACCEPT' if 'accept' in form else 'DROP'

        try:
            validate.add_firewall_rule(fields)
            if (fields.dst_port):
                validate.network_port(fields.dst_port)

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

            with IPTableManager() as iptables:
                iptables.add_rule(fields)

    elif ('change_interface' not in form):
        return INVALID_FORM, zone

    return error, zone

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
            with IPTableManager() as iptables:
                iptables.delete_nat(fields)

    elif (action == 'add'):
        try:
            validate.add_dnat_rule(fields)
            if (fields.protocol in ['tcp', 'udp']):
                validate.network_port(fields.dst_port)
                validate.network_port(fields.host_port)

            validate.ip_address(fields.host_ip)

        except ValidationError as ve:
            error = ve
        else:
            with IPTableManager() as iptables:
                iptables.add_nat(fields)

            configure.add_open_wan_protocol(fields)
    else:
        return INVALID_FORM, zone

    return error, zone

def _snat_rules(zone, action, form):
    error = None
    print(333333, form)
    fields = SimpleNamespace(**form)

    # TODO: make this code for snat (currently using dnat code as template)
    if (action == 'remove'):
        try:
            # NOTE: validation needs to know the zone so it can ensure the position is valid
            validate.del_nat_rule(fields)
        except ValidationError as ve:
            error = ve

        else:
            with IPTableManager() as iptables:
                iptables.delete_nat(fields)

    elif (action == 'add'):
        try:
            validate.add_snat_rule(fields)

            validate.ip_address(ip_iter=[fields.orig_src_ip, fields.new_src_ip])

        except ValidationError as ve:
            error = ve
        else:
            with IPTableManager() as iptables:
                iptables.add_nat(fields)

    else:
        return INVALID_FORM, zone

    return error, zone