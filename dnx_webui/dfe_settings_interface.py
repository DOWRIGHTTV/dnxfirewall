#!/usr/bin/python3

import sys, os
import time

HOME_DIR = os.environ.get('HOME_DIR', os.path.dirname(os.path.dirname((os.path.realpath('__file__')))))
sys.path.insert(0, HOME_DIR)

import dnx_sysmods.configure.configure as configure
import dnx_iptools.interface_ops as interface
import dnx_sysmods.configure.web_validate as validate

from dnx_sysmods.configure.def_constants import CFG, DATA, INTF, INVALID_FORM
from dnx_sysmods.configure.file_operations import load_configuration
from dnx_sysmods.configure.exceptions import ValidationError
from dnx_sysmods.configure.system_info import System, Interface


_IP_DISABLED = True

def load_page(form):
    interface_settings = load_configuration('config')

    wan_settings = interface_settings['interfaces']['builtins']['wan']

    interface_settings = {
        'mac': {
            'default': wan_settings['default_mac'],
            'current': wan_settings['default_mac'] if not wan_settings['configured_mac'] else wan_settings['configured_mac']
        },
        'ip': {
            'state': wan_settings['state'],
            'ip_address': f'{interface.get_ip_address(interface=wan_settings["ident"])}',
            'netmask': f'{interface.get_netmask(interface=wan_settings["ident"])}',
            'default_gateway': Interface.default_gateway(wan_settings["ident"])
        }
    }

    return interface_settings

def update_page(form):
    if ('update_wan_state' in form):
        wan_state = form.get('update_wan_state', DATA.INVALID)
        if wan_state is DATA.INVALID:
            return INVALID_FORM

        try:
            wan_state = INTF(validate.convert_int(wan_state))
        except (ValidationError, KeyError):
            return INVALID_FORM

        else:
            configure.set_wan_interface(wan_state)

    elif ('update_wan_ip' in form):
        wan_ip_settings = {
            'ip': form.get('wan_ip', DATA.INVALID),
            'cidr': form.get('wan_cidr', DATA.INVALID),
            'dfg': form.get('wan_dfg', DATA.INVALID)
        }

        if (DATA.INVALID in wan_ip_settings.values()):
            return INVALID_FORM

        try:
            validate.ip_address(wan_ip_settings['ip'])
            validate.cidr(wan_ip_settings['cidr'])
            validate.ip_address(wan_ip_settings['dfg'])
        except ValidationError as ve:
            return ve

        configure.set_wan_ip(wan_ip_settings)

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
                configure.set_wan_interface(wan_settings)

        else:
            # no arg indicates dynamic ip/dhcp assignment
            configure.set_wan_interface()

    elif ('wan_mac_update' in form):
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

    else:
        return INVALID_FORM
