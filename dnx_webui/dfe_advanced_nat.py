#!/usr/bin/python3

from types import SimpleNamespace

import dnx_routines.configure.configure as configure
import dnx_routines.configure.web_validate as validate

from dnx_gentools.def_constants import INVALID_FORM, DATA
from dnx_routines.configure.exceptions import ValidationError
from dnx_routines.configure.iptables import IPTablesManager
from dnx_routines.configure.system_info import System

def load_page():
    return {
        'dmz_dnat_rules': System.nat_rules(),
        'local_snat_rules': System.nat_rules(nat_type='SRCNAT')
    }

# TODO: fix inconcistent variable names for nat rules
def update_page(form):
    error = None

    # action field is not required for some functions, so will not be hard validated
    action = form.get('action', DATA.MISSING)

    nat_type = form.get('nat_type', None)
    if (nat_type in ['DSTNAT', 'SRCNAT']):

        if (nat_type == 'DSTNAT'):
            error = _dnat_rules(action, form)

        elif (nat_type == 'SRCNAT'):
            error = _snat_rules(action, form)

    else:
        return INVALID_FORM, None, None

    # updating page data then returning. this is because we need to serve the content with the newly added
    # configuration item.
    page_data = {
        'dmz_dnat_rules': System.nat_rules(),
        'local_snat_rules': System.nat_rules(nat_type='SRCNAT')
    }

    # print(f'RETURNING: {page_data}')
    return error, None, page_data

# TODO: currently it is possible to put overlapping DNAT rules (same dst port, but different host port).
    # this isnt normally an issue and could be left to the user, but the last one inserted with be
    # the local port value, which if the lower rule, will be incorrect for portscan reject packets.
    # a similar issue will also be for the local ports because they are flipped when loaded into the
    # ips.
        # NOTE: a possible solution would be to store the wan ip/wan port and local ip/ local port in a tuple
        # or a splittable string. this could be the key/vals to the dict making each unique and would allow
        # for any combination and still properly identify missed scans while also reliable generating reject
        # packets.
def _dnat_rules(action, form):
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
        return INVALID_FORM

    return error

def _snat_rules(action, form):
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
        return INVALID_FORM

    return error
