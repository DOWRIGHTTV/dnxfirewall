#!/usr/bin/python3

import sys, os
import time
import json

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import CFG, DATA, INVALID_FORM
from dnx_iptools.dnx_protocol_tools import convert_mac_to_string as mac_str
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_system_info import Services

def load_page():
    dhcp_server = load_configuration('dhcp_server.json')['dhcp_server']
    dhcp_res_list = dhcp_server['reservations']

    return {'reservations': {
        mac_str(mac): info for mac, info in dhcp_res_list.items()}
    }

#TODO: figure out a way to ensure duplicate ip addresses cannot have a reservation created. currently we
# use the mac address as the key/identifier which would allow for different macs to be configured with the
# same ip address.
def update_page(form):
    if ('dhcp_res_add' in form):
        dhcp_settings = {
            'zone': form.get('zone', DATA.INVALID),
            'mac': form.get('mac_address', ''),
            'ip': form.get('ip_address', DATA.INVALID),
            'description': form.get('description', DATA.INVALID)
        }

        if (DATA.INVALID in dhcp_settings.values()):
            return INVALID_FORM

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
