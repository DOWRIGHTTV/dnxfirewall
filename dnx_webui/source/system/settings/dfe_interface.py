#!/usr/bin/python3

import dnx_iptools.interface_ops as interface

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.def_enums import CFG, DATA, INTF
from dnx_gentools.file_operations import load_configuration, config

from dnx_iptools.cprotocol_tools import itoip

from dnx_routines.configure.web_validate import ValidationError, convert_int, ip_address
from dnx_routines.configure.system_info import Interface

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from dnx_gentools.file_operations import ConfigChain


_IP_DISABLED = True

def load_page(_):
    system_settings: ConfigChain = load_configuration('system')

    wan_ident = system_settings['interfaces->builtins->wan->ident']
    wan_state = system_settings['interfaces->builtins->wan->state']
    default_mac = system_settings['interfaces->builtins->wan->default_mac']
    configured_mac = system_settings['interfaces->builtins->wan->default_mac']

    interface_settings = {
        'mac': {
            'default': default_mac,
            'current': configured_mac if configured_mac else default_mac
        },
        'ip': {
            'state': wan_state,
            'ip_address': itoip(interface.get_ipaddress(interface=wan_ident)),
            'netmask': itoip(interface.get_netmask(interface=wan_ident)),
            'default_gateway': itoip(Interface.default_gateway(wan_ident))
        }
    }

    return interface_settings

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
        wan_ip = form.get('ud_wan_ip', None)
        cidr = form.get('ud_wan_cidr', None)
        default_gateway = form.get('ud_wan_dfg', None)
        # missing forms keys. potential client side manipulation
        if any(x is None for x in [wan_ip, cidr, default_gateway]):
            return INVALID_FORM

        if ('static_wan' in form):
            # keys present, but fields left empty. (unable to force client side)
            if (not wan_ip or not default_gateway):
                return 'All fields are required when setting the wan interface to static.'

            try:
                validate.ip_address(wan_ip)
                validate.cidr(cidr)
                validate.default_gateway(default_gateway)
            except ValidationError as ve:
                return ve
            else:
                wan_settings = {
                    'ip_address': wan_ip, 'cidr': cidr, 'default_gateway': default_gateway
                }
                interface.set_wan_interface(wan_settings)

        else:
            # no arg indicates dynamic ip/dhcp assignment
            interface.set_wan_interface()

    elif ('wan_mac_update' in form):
        mac_address = form.get('ud_wan_mac', None)
        if (not mac_address):
            return INVALID_FORM

        try:
            validate.mac_address(mac_address)
        except ValidationError as ve:
            return ve
        else:
            interface.set_wan_mac(CFG.ADD, mac_address=mac_address)

    elif ('wan_mac_restore' in form):
        interface.set_wan_mac(CFG.DEL)

    else:
        return INVALID_FORM
