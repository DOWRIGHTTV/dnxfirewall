#!/usr/bin/python3

import sys, os
import time

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_iptools.dnx_interface as interface
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import CFG, INVALID_FORM
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_system_info import System, Interface


_IP_DISABLED = True

def load_page():
    interface_settings = load_configuration('config')

    wan_settings = interface_settings['interfaces']['wan']
    print(wan_settings)

    interface_settings = {
        'mac': {
            'default': wan_settings['default_mac'],
            'current': wan_settings['default_mac'] if not wan_settings['configured_mac'] else wan_settings['configured_mac']
        },
        'ip': {
            'dhcp': wan_settings['dhcp'],
            'ip_address': f'{interface.get_ip_address(interface=wan_settings["ident"])}',
            'netmask': f'{interface.get_netmask(interface=wan_settings["ident"])}',
            'default_gateway': Interface.default_gateway(wan_settings["ident"])
        }
    }

    return interface_settings

def update_page(form):
    print(form)

    if (_IP_DISABLED):
        return 'wan interface configuration currently disabled for system rework.'

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

    elif ('wan_mac_restore' in form):
        configure.set_wan_mac(CFG.DEL)

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
