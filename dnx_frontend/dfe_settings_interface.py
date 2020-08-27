#!/usr/bin/python3

import sys, os
import time

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import CFG, INVALID_FORM
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_system_info import System, Interface


_IP_DISABLED = True

def load_page():
    interface_settings = load_configuration('config')['settings']

    wan_int = interface_settings['interfaces']['wan']
    default_wan_mac = wan_int['default_mac']
    configured_wan_mac = wan_int['configured_mac']
    dhcp = wan_int['dhcp']
    wan_int = wan_int['ident']

    # TODO: migrate away from instace
    Int = Interface()
    wan_ip = Int.ip_address(wan_int)
    wan_netmask = Int.netmask(wan_int)
    wan_dfg = Int.default_gateway(wan_int)

    current_wan_mac = default_wan_mac if not configured_wan_mac else configured_wan_mac

    interface_settings = {
        'mac': {
            'default': default_wan_mac,
            'current': current_wan_mac
        },
        'ip': {
            'dhcp': dhcp,
            'ip_address': wan_ip,
            'netmask': wan_netmask,
            'default_gateway': wan_dfg
        }
    }

    return interface_settings

def update_page(form):
    ## Matching wan MAC Address Update and sending to configuration method
    if ('wan_mac_update' in form):
        mac_address = form.get('ud_wan_mac', None)
        if (not mac_address):
            return INVALID_FORM

        try:
            validate.mac_address(mac_address)
        except ValidationError as ve:
            return ve
        else:
            configure.set_wan_mac(CFG.ADD, mac_address=mac_address)

    ## Matching wan MAC Address Restore to Default and sending to configuration method
    elif ('wan_mac_restore' in form):
        configure.set_wan_mac(CFG.DEL)

    if (_IP_DISABLED):
        return 'ip address configuration currently disabled for system rework.'

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
                configure.set_wan_interface(wan_settings)

        else:
            # no arg indicates dynamic ip/dhcp assignment
            configure.set_wan_interface()

    return INVALID_FORM
