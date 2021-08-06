#!/usr/bin/python3

import json
import sys, os

from types import SimpleNamespace

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import INVALID_FORM, DATA
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_iptables import IPTablesManager
from dnx_configure.dnx_system_info import System, Services

NETMASKS = [*list(reversed(range(24,33))), 16, 8, 0]

valid_zones = {
    'GLOBAL_ZONE': '1',
    'WAN_ZONE': '2',
    'DMZ_ZONE': '3',
    'LAN_ZONE': '4'
}

zone_convert = {
    '1': 'GLOBAL_ZONE',
    '2': 'WAN_ZONE',
    '3': 'DMZ_ZONE',
    '4': 'LAN_ZONE'
}

valid_standard_rule_fields = {
    'position','src_ip','src_netmask','dst_ip','dst_netmask','protocol','dst_port'
}

def load_page():
    return {
        'firewall_rules': System.firewall_rules(),
        'dmz_dnat_rules': System.nat_rules(),
        'local_snat_rules': System.nat_rules(nat_type='SRCNAT'),
        'netmasks': NETMASKS
    }

# TODO: fix inconcistent variable names for nat rules
def update_page(form):
    print(form)
    # initial input validation for presence of zone field
    zone = form.get('zone', None)
    if (zone not in valid_zones):
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
            configure.del_open_wan_protocol(fields)

            with IPTablesManager() as iptables:
                iptables.delete_nat(fields)

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
            configure.add_open_wan_protocol(fields)

            with IPTablesManager() as iptables:
                iptables.add_nat(fields)

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
