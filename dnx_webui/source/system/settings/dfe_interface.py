#!/usr/bin/python3

import dnx_iptools.interface_ops as interface

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.def_enums import CFG, DATA, INTF
from dnx_gentools.file_operations import load_configuration, config

from dnx_iptools.cprotocol_tools import itoip

from source.web_typing import *
from source.web_validate import ValidationError, convert_int, ip_address, default_gateway, cidr


_IP_DISABLED = True

def load_page(_):
    system_settings: ConfigChain = load_configuration('system')

    wan_ident: str = system_settings['interfaces->builtins->wan->ident']
    wan_state: int = system_settings['interfaces->builtins->wan->state']
    default_mac:    str = system_settings['interfaces->builtins->wan->default_mac']
    configured_mac: str = system_settings['interfaces->builtins->wan->default_mac']

    return {
        'mac': {
            'default': default_mac,
            'current': configured_mac if configured_mac else default_mac
        },
        'ip': {
            'state': wan_state,
            'ip_address': itoip(interface.get_ipaddress(interface=wan_ident)),
            'netmask': itoip(interface.get_netmask(interface=wan_ident)),
            'default_gateway': itoip(interface.default_route())
        }
    }

def update_page(form: dict):
    if ('update_wan_state' in form):
        wan_state = form.get('update_wan_state', DATA.MISSING)
        if (wan_state is DATA.MISSING):
            return INVALID_FORM

        try:
            wan_state = INTF(convert_int(wan_state))
        except (ValidationError, KeyError):
            return INVALID_FORM

        else:
            interface.set_wan_interface(wan_state)

    elif ('update_wan_ip' in form):
        wan_ip_settings = config(**{
            'ip': form.get('wan_ip', DATA.MISSING),
            'cidr': form.get('wan_cidr', DATA.MISSING),
            'dfg': form.get('wan_dfg', DATA.MISSING)
        })

        if (DATA.MISSING in wan_ip_settings.values()):
            return INVALID_FORM

        try:
            ip_address(wan_ip_settings.ip)
            cidr(wan_ip_settings.cidr)
            ip_address(wan_ip_settings.dfg)
        except ValidationError as ve:
            return ve

        interface.set_wan_ip(wan_ip_settings)

    elif (_IP_DISABLED):
        return 'wan interface configuration currently disabled for system rework.'

    elif ('wan_ip_update' in form):
        wan_settings = config(**{
            'ip': form.get('ud_wan_ip', DATA.MISSING),
            'cidr': form.get('ud_wan_cidr', DATA.MISSING),
            'dfg': form.get('ud_wan_dfg', DATA.MISSING)
        })

        if (DATA.MISSING in wan_settings.values()):
            return INVALID_FORM

        if ('static_wan' in form):
            # keys present, but fields left empty (unable to force client side).
            # catching prior to validation to give a more graceful error response
            if (not wan_settings.ip or not wan_settings.dfg):
                return 'All fields are required when setting the wan interface to static.'

            try:
                ip_address(wan_settings.ip)
                cidr(wan_settings.cidr)
                default_gateway(wan_settings.dfg)
            except ValidationError as ve:
                return ve

            else:
                interface.set_wan_interface(wan_settings)

        else:
            # no arg indicates dynamic ip/dhcp assignment
            interface.set_wan_interface()

    elif ('wan_mac_update' in form):
        mac_address = form.get('ud_wan_mac', None)
        if (not mac_address):
            return INVALID_FORM

        try:
            mac_address(mac_address)
        except ValidationError as ve:
            return ve
        else:
            interface.set_wan_mac(CFG.ADD, mac_address=mac_address)

    elif ('wan_mac_restore' in form):
        interface.set_wan_mac(CFG.DEL)

    else:
        return INVALID_FORM
