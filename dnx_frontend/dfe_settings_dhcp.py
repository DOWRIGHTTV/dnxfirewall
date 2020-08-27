#!/usr/bin/python3

import sys, os
import time
import json

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import CFG, INVALID_FORM
from dnx_iptools.dnx_protocol_tools import convert_mac_to_string as m2s
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_system_info import Services

def load_page():
    dhcp_server = load_configuration('dhcp_server.json')['dhcp_server']
    dhcp_res_list = dhcp_server['reservations']

    return {'reservations': {
        m2s(mac): info for mac, info in dhcp_res_list.items()}
    }

def update_page(form):
    if ('dhcp_res_add' in form):
        mac_address = form.get('mac_address', '').lower()
        ip_address = form.get('ip_address', None)
        username = form.get('res_name', None)
        if not all([mac_address, ip_address, username]):
            return INVALID_FORM

        dhcp_settings = {'mac': mac_address, 'ip': ip_address, 'username': username}
        try:
            validate.dhcp_reservation(dhcp_settings)
        except ValidationError as ve:
            return ve
        else:
            configure.set_dhcp_reservation(dhcp_settings, CFG.ADD)

    # Matching DHCP reservation REMOVE and sending to configuration method.
    elif ('dhcp_res_remove' in form):
        mac_address = form.get('dhcp_res_remove', None)
        if (not mac_address):
            return INVALID_FORM

        try:
            validate.mac_address(mac_address)
        except ValidationError as ve:
            return ve
        else:
            dhcp_settings = {'mac': mac_address}

            configure.set_dhcp_reservation(dhcp_settings, CFG.DEL)

    else:
        return INVALID_FORM
