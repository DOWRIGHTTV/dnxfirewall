#!/usr/bin/python3

from __future__ import annotations

from typing import Optional, Any
from ipaddress import IPv4Network, IPv4Address

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.def_enums import CFG, DATA, DHCP
from dnx_gentools.file_operations import ConfigurationManager, config, load_configuration, load_data

from dnx_iptools.protocol_tools import mac_add_sep as mac_str

from dnx_routines.configure.web_validate import ValidationError, standard, mac_address, ip_address, get_convert_int, get_convert_bint
from dnx_routines.configure.system_info import System

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from dnx_gentools.file_operations import ConfigChain


def load_page(form) -> dict[str, Any]:
    dhcp_server: ConfigChain = load_configuration('dhcp_server')
    dhcp_leases: dict = load_data('dhcp_server.lease')

    leases = []
    for ip, (status, handout_time, mac, hostname) in dhcp_leases.items():

        # ensuring only leased status entries get included
        if (status == DHCP.LEASED):
            offset_time = System.calculate_time_offset(handout_time)
            handout_time = System.format_date_time(offset_time)

            leases.append((ip, handout_time, mac_str(mac), hostname))

    leases.sort()

    dhcp_settings = {
        'interfaces': dhcp_server.get_dict('interfaces->builtins'),
        'reservations': [(mac_str(mac), info) for mac, info in dhcp_server.get_items('reservations')],
        'leases': leases
    }

    return dhcp_settings

# TODO: figure out a way to ensure duplicate ip addresses cannot have a reservation created. currently we
#  use the mac address as the key/identifier which would allow for different macs to be configured with the
#  same ip address.
def update_page(form):

    if ('general_settings' in form):
        server_settings = config(**{
            'interface': form.get('interface', DATA.MISSING),

            # NOTE: switch does not post field if disabled. if not present, the server will disable the
            # corresponding field as normal.
            'enabled': get_convert_bint(form, 'server_enabled'),
            'icmp_check': get_convert_bint(form, 'icmp_check'),

            'lease_range': {
                'start': get_convert_int(form, 'start'),
                'end': get_convert_int(form, 'end')
            }
        })

        if (x in [DATA.MISSING, DATA.INVALID] for x in server_settings.values()):
            return INVALID_FORM

        error = validate_dhcp_settings(server_settings)
        if (error):
            return error.message

        configure_dhcp_settings(server_settings)

    elif ('dhcp_res_add' in form):
        dhcp_settings = config(**{
            'zone': form.get('zone', DATA.MISSING),
            'mac': form.get('mac_address', DATA.MISSING),
            'ip': form.get('ip_address', DATA.MISSING),
            'description': form.get('description', DATA.MISSING)
        })

        if (DATA.MISSING in dhcp_settings.values()):
            return INVALID_FORM

        error = validate_reservation(dhcp_settings)
        if (error):
            return error.message

            # will raise exception if ip address is already reserved
        configure_reservation(dhcp_settings, CFG.ADD)

    # Matching DHCP reservation REMOVE and sending to configuration method.
    elif ('dhcp_res_remove' in form):
        dhcp_settings = config(**{
            'mac': form.get('dhcp_res_remove', DATA.MISSING)
        })

        if (DATA.MISSING in dhcp_settings.values()):
            return INVALID_FORM

        try:
            mac_address(dhcp_settings.mac_addr)
        except ValidationError as ve:
            return ve

        configure_reservation(dhcp_settings, CFG.DEL)

    elif ('dhcp_lease_remove' in form):
        ip_addr = form.get('dhcp_lease_remove', DATA)
        if (ip_addr is DATA.MISSING):
            return INVALID_FORM

        try:
            ip_address(ip_addr)

            remove_dhcp_lease(ip_addr)
        except ValidationError as ve:
            return ve

    else:
        return INVALID_FORM

# ==============
# VALIDATION
# ==============
def validate_dhcp_settings(settings: config, /) -> Optional[ValidationError]:
    if (settings.interface not in ['lan', 'dmz']):
        return ValidationError('Invalid interface referenced.')

    lease_range = settings.lease_range

    # clamping the valid range into lan/dmz class C's.
    # this will have to change later if more control over interface configurations is implemented.
    for field in lease_range.values():

        if (field not in range(2, 255)):
            return ValidationError('DHCP ranges must be between 2 and 254.')

    if (lease_range['start'] >= lease_range['end']):
        return ValidationError('DHCP pool start value must be less than the end value.')

def validate_reservation(res, /) -> Optional[ValidationError]:
    standard(res.description, override=[' '])
    mac_address(res.mac)
    ip_address(res.ip)

    dhcp_settings = load_configuration('system')

    zone_net = IPv4Network(dhcp_settings[f'interfaces->builtins{res.zone.lower()}->subnet'])
    if (IPv4Address(res.ip) not in zone_net.hosts()):
        return ValidationError(f'IP Address must fall within {zone_net} range.')

# ==============
# CONFIGURATION
# ==============
def configure_dhcp_settings(dhcp_settings):
    with ConfigurationManager('dhcp_server') as dnx:
        dhcp_server_settings = dnx.load_configuration()

        expanded_data = dhcp_server_settings.expanded_user_data

        interface = dhcp_settings.pop('interface')
        expanded_data['interfaces']['builtins'][interface].update(dhcp_settings)

        dnx.write_configuration(expanded_data)

def configure_reservation(dhcp: config, action: CFG) -> None:
    with ConfigurationManager('dhcp_server') as dnx:

        dhcp_server_settings = dnx.load_configuration()

        if (action is CFG.ADD):

            dhcp_leases = load_data('dhcp_server.lease')
            configured_reservations = dhcp_server_settings.searchable_user_data['reservations']
            reserved_ips = {host['ip_address'] for host in configured_reservations}

            # preventing reservations being created for ips with an active dhcp lease
            if (dhcp.ip in dhcp_leases):
                raise ValidationError(
                    f'There is an active lease with {dhcp.ip}. Clear the lease and try again.'
                )

            # ensuring mac address and ip address are unique
            if (dhcp.mac in configured_reservations or dhcp.ip in reserved_ips):
                raise ValidationError(f'{dhcp.ip} is already reserved.')

            host_path = f'reservations->{dhcp.mac.replace(":", "")}'

            dhcp_server_settings[f'{host_path}->zone'] = dhcp.zone
            dhcp_server_settings[f'{host_path}->ip_address'] = dhcp.ip
            dhcp_server_settings[f'{host_path}->description'] = dhcp.description

        elif (action is CFG.DEL):
            del dhcp_server_settings[f'reservations->{dhcp.mac}']

        dnx.write_configuration(dhcp_server_settings.expanded_user_data)

def remove_dhcp_lease(ip_addr: str) -> None:
    with ConfigurationManager('dhcp_server') as dnx:
        dhcp_leases = dnx.load_configuration()

        try:
            del dhcp_leases[f'leases->{ip_addr}']
        except KeyError:
            raise ValidationError(INVALID_FORM)

        dnx.write_configuration(dhcp_leases.expanded_user_data)
