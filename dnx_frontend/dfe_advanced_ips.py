#!/usr/bin/env python3

import os, sys
import json

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import CFG, INVALID_FORM
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_system_info import Services

def load_page():
    ips = load_configuration('ips.json')['ips']

    passive_block_ttl = ips['passive_block_ttl']
    ids_mode = ips['ids_mode']

    # ddos settings
    ddos_enabled = ips['ddos']['enabled']
    tcp_src_limit  = ips['ddos']['limits']['source']['tcp']
    udp_src_limit  = ips['ddos']['limits']['source']['udp']
    icmp_src_limit = ips['ddos']['limits']['source']['icmp']
    ddos_settings = {
        'enabled': ddos_enabled, 'tcp': tcp_src_limit,
        'udp': udp_src_limit, 'icmp': icmp_src_limit
    }

    # portscan settings
    portscan_prevention = ips['port_scan']['enabled']
    portscan_reject = ips['port_scan']['reject']
    portscan_settings = {
        'enabled': portscan_prevention, 'reject': portscan_reject
    }

    # ips host/ configured dns server whitelist
    ip_whitelist = ips['whitelist']['ip_whitelist']
    dns_server_whitelist = ips['whitelist']['dns_servers']

    ips_enabled = bool(ddos_enabled or portscan_prevention)

    # TODO: clean this shit up.
    tcp_nat = ips['open_protocols']['tcp']
    udp_nat = ips['open_protocols']['udp']

    nats_configured = tcp_nat or udp_nat
    if (not nats_configured):
        ddos_notify = True if not ddos_enabled else False
        ps_notify = True if not portscan_prevention else False
    else:
        ddos_notify = False
        ps_notify = False

    ips_settings = {
        'enabled': ips_enabled, 'length': passive_block_ttl, 'ids_mode': ids_mode,
        'ddos': ddos_settings, 'port_scan': portscan_settings, 'ddos_notify': ddos_notify,
        'ps_notify': ps_notify, 'ip_whitelist': ip_whitelist, 'dns_server_whitelist': dns_server_whitelist
    }

    return ips_settings

## Called when front end post, parsing web forms, calling updater methods ##
def update_page(form):
    # Matching logging update form and sending to configuration method.
    if ('dnx_ddos_update' in form):
        action = CFG.ADD if 'ddos' in form else CFG.DEL

        ddos_limits = {}
        for protocol in ['tcp', 'udp', 'icmp']:
            form_limit = form.get(f'{protocol}_limit', None)
            if (form_limit is None):
                return INVALID_FORM

            if (form_limit == ''): continue

            limit = validate.convert_int(form_limit)
            if (not limit):
                return f'{protocol} limit must be an integer or left empty.'

            if (not 10 <= limit <= 200):
                return f'{protocol} limit must be in range 20-200.'

            ddos_limits[protocol] = form_limit

        configure.set_ips_ddos(action)

        if (ddos_limits):
            configure.set_ips_ddos_limits(ddos_limits)

    elif ('dnx_portscan_update' in form):
        enabled_settings = form.getlist('ps_settings', None)
        try:
            validate.portscan_settings(enabled_settings)
        except ValidationError as ve:
            return ve
        else:
            configure.set_ips_portscan(enabled_settings)

    elif ('general_settings' in form):
        ids_mode = True if 'ids_mode' in form else False
        passive_block_length = form.get('passive_block_length', None)
        if (not passive_block_length):
            return INVALID_FORM

        try:
            pb_length = validate.ips_passive_block_length(passive_block_length)
        except ValidationError as ve:
           return ve
        else:
            configure.set_ips_general_settings(pb_length, ids_mode)

    elif ('ips_wl_add' in form):
        whitelist_ip = form.get('ips_wl_ip', None)
        whitelist_name = form.get('ips_wl_name', None)
        if (not whitelist_ip or not whitelist_name):
            return INVALID_FORM

        try:
            validate.ip_address(whitelist_ip)
            validate.standard(whitelist_name)
        except ValidationError as ve:
            return ve
        else:
            configure.update_ips_ip_whitelist(whitelist_ip, whitelist_name, CFG.ADD)

    elif ('ips_wl_remove' in form):
        whitelist_ip = form.get('ips_wl_ip', None)
        if (not whitelist_ip):
            return INVALID_FORM

        try:
            validate.ip_address(whitelist_ip)
        except ValidationError as ve:
            return ve
        else:
            configure.update_ips_ip_whitelist(whitelist_ip, None, CFG.DEL)

    elif ('ips_wl_dns' in form):
        action = CFG.ADD if 'dns_enabled' in form else CFG.DEL

        configure.update_ips_dns_whitelist(action)

    else:
        return INVALID_FORM
