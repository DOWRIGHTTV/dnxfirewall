#!/usr/bin/python3

from __future__ import annotations

from ipaddress import IPv4Network, IPv4Address

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_enums import CFG, DATA, DHCP
from dnx_gentools.def_namedtuples import DHCP_RECORD
from dnx_gentools.file_operations import ConfigurationManager, config, load_configuration, load_data

from dnx_iptools.cprotocol_tools import itoip
from dnx_iptools.protocol_tools import mac_add_sep as mac_str

from dnx_gentools.system_info import System

from source.web_interfaces import StandardWebPage

__all__ = ('WebPage',)

VALID_DHCP_INTERFACES = ['lan', 'dmz']

class WebPage(StandardWebPage):
    '''
    available methods: load, update
    '''
    @staticmethod
    def load(_: Form) -> dict[str, Any]:
        dhcp_server: ConfigChain = load_configuration('dhcp_server', cfg_type='global')

        # if dhcp server isn't enabled and/or there was never a lease, the file wont exist.
        try:
            dhcp_leases: dict[str, tuple] = load_data('dhcp_server.lease', filepath='dnx_profile/data/usr')
        except FileNotFoundError:
            dhcp_leases = {}

        leases = []
        for ip, _record in dhcp_leases.items():
            record = DHCP_RECORD(*_record)

            # json key is str repr of int.
            ip = itoip(int(ip))

            # ensuring only leased status entries get included
            if (record.rtype == DHCP.LEASED):
                offset_time = System.calculate_time_offset(record.timestamp)
                handout_time = System.format_date_time(offset_time)

                leases.append((ip, handout_time, mac_str(record.mac), record.hostname))

        leases.sort()

        intf_settings = {}
        interfaces: dict[str, dict] = dhcp_server.get_dict('interfaces->builtin')
        for intf, settings in interfaces.items():

            # converting 32-bit int to range delta
            net_start: int = settings['options']['3'][1]
            start: int = settings['lease_range'][0]
            end:   int = settings['lease_range'][1]

            settings['lease_range'] = [start - net_start, end - net_start]

            intf_settings[intf] = settings

        return {
            'interfaces': intf_settings,
            'reservations': [(mac_str(mac), info) for mac, info in dhcp_server.get_items('reservations')],
            'leases': leases
        }

    @staticmethod
    def update(form: Form) -> tuple[int, str]:

        server_settings = config()
        switch_change = False

        # TODO: this will need to be improved when the multiple interfaces functionality is implemented
        if ('lan/enabled' in form):
            cfg_val = get_convert_bint(form, 'lan/enabled')

            server_settings = config(**{
                'interface': 'lan',
                'cfg_key': 'enabled',
                'cfg_val': cfg_val
            })

            switch_change = True

        elif ('lan/icmp_check' in form):
            cfg_val = get_convert_bint(form, 'lan/icmp_check')

            server_settings = config(**{
                'interface': 'lan',
                'cfg_key': 'icmp_check',
                'cfg_val': cfg_val
            })

            switch_change = True

        elif ('dmz/enabled' in form):
            cfg_val = get_convert_bint(form, 'dmz/enabled')

            server_settings = config(**{
                'interface': 'dmz',
                'cfg_key': 'enabled',
                'cfg_val': cfg_val
            })

            switch_change = True

        elif ('dmz/icmp_check' in form):
            cfg_val = get_convert_bint(form, 'dmz/icmp_check')

            server_settings = config(**{
                'interface': 'dmz',
                'cfg_key': 'icmp_check',
                'cfg_val': cfg_val
            })

            switch_change = True

        if (switch_change):
            if any([x in [DATA.MISSING, DATA.INVALID] for x in server_settings.values()]):
                return 1, INVALID_FORM

            configure_dhcp_switches(server_settings)

            return NO_STANDARD_ERROR

        if ('general_settings' in form):
            server_settings = config(**{
                'interface': form.get('general_settings', DATA.MISSING),
                'lease_range': [
                    get_convert_int(form, 'start'),
                    get_convert_int(form, 'end')
                ]
            })

            if error := validate_dhcp_settings(server_settings):
                return 2, error.message

            configure_dhcp_settings(server_settings)

        elif ('dhcp_res_add' in form):
            dhcp_settings = config(**{
                'zone': form.get('zone', DATA.MISSING),
                'mac': form.get('mac_address', DATA.MISSING),
                'ip': form.get('ip_address', DATA.MISSING),
                'description': form.get('description', DATA.MISSING)
            })

            if (DATA.MISSING in dhcp_settings.values()):
                return 3, INVALID_FORM

            if error := validate_reservation(dhcp_settings):
                return 4, error.message

            # returns exception if ip address is already reserved
            if error := configure_reservation(dhcp_settings, CFG.ADD):
                return 5, error.message

        elif ('dhcp_res_remove' in form):
            dhcp_settings = config(**{
                'mac': form.get('dhcp_res_remove', DATA.MISSING)
            })

            if (DATA.MISSING in dhcp_settings.values()):
                return 6, INVALID_FORM

            try:
                mac_address(dhcp_settings.mac)
            except ValidationError as ve:
                return 7, ve.message

            configure_reservation(dhcp_settings, CFG.DEL)

        elif ('dhcp_lease_remove' in form):
            ip_addr = form.get('dhcp_lease_remove', DATA)
            if (ip_addr is DATA.MISSING):
                return 8, INVALID_FORM

            try:
                ip_address(ip_addr)
            except ValidationError as ve:
                return 9, ve.message

            if error := remove_dhcp_lease(ip_addr):
                return 10, error.message


        else:
            return 99, INVALID_FORM

        return NO_STANDARD_ERROR

# ==============
# VALIDATION
# ==============
def validate_dhcp_settings(settings: config, /) -> Optional[ValidationError]:
    if (settings.interface not in VALID_DHCP_INTERFACES):
        return ValidationError('Invalid interface referenced.')

    lrange = settings.lease_range
    # clamping the valid range into lan/dmz class C's.
    # this will have to change later if more control over interface configurations is implemented.
    if any([x not in range(2, 255) for x in lrange]):
        return ValidationError('DHCP ranges must be between 2 and 254.')

    if (lrange[0] >= lrange[1]):
        return ValidationError('The DHCP pool start value must be less than the end value.')

def validate_reservation(res: config, /) -> Optional[ValidationError]:
    ip_address(res.ip)
    mac_address(res.mac)
    standard(res.description, override=[' '])

    dhcp_settings: ConfigChain = load_configuration('system', cfg_type='global')

    zone_net = IPv4Network(dhcp_settings[f'interfaces->builtin->{res.zone.lower()}->subnet'])
    if (IPv4Address(res.ip) not in zone_net.hosts()):
        return ValidationError(f'IP Address must fall within {zone_net} range.')

# ==============
# CONFIGURATION
# ==============
def configure_dhcp_switches(dhcp_settings: config):
    with ConfigurationManager('dhcp_server', cfg_type='global') as dnx:
        server_settings: ConfigChain = dnx.load_configuration()

        interface = dhcp_settings.pop('interface')

        config_path = f'interfaces->builtin->{interface}'

        server_settings[f'{config_path}->{dhcp_settings.cfg_key}'] = dhcp_settings.cfg_val

        dnx.write_configuration(server_settings.expanded_user_data)
def configure_dhcp_settings(dhcp_settings: config):
    with ConfigurationManager('dhcp_server', cfg_type='global') as dnx:
        server_settings: ConfigChain = dnx.load_configuration()

        interface = dhcp_settings.pop('interface')

        config_path = f'interfaces->builtin->{interface}'
        # ...this is excessive
        configured_options: dict = server_settings.get_dict(f'{config_path}->options')

        dhcp_settings.lease_range[0] += configured_options['3'][1]  # ip delta
        dhcp_settings.lease_range[1] += configured_options['3'][1]  # ip delta

        server_settings[f'{config_path}->lease_range'] = dhcp_settings.lease_range

        dnx.write_configuration(server_settings.expanded_user_data)

def configure_reservation(dhcp: config, action: CFG) -> Optional[ValidationError]:
    with ConfigurationManager('dhcp_server', cfg_type='global') as dnx:
        dhcp_server_settings: ConfigChain = dnx.load_configuration()

        if (action is CFG.ADD):
            # preventing reservations being created for ips with an active dhcp lease
            dhcp_leases = load_data('dhcp_server.lease', cfg_type='system/global')
            if (dhcp.ip in dhcp_leases):
                return ValidationError(f'There is an active lease for {dhcp.ip}. Clear the lease and try again.')

            configured_reservations = dhcp_server_settings.get_values('reservations')
            reserved_ips = {host['ip_address'] for host in configured_reservations}

            # ensuring mac address and ip address are unique
            if (dhcp.mac in configured_reservations or dhcp.ip in reserved_ips):
                return ValidationError(f'{dhcp.ip} is already reserved.')

            host_path = f'reservations->{dhcp.mac.replace(":", "")}'

            dhcp_server_settings[f'{host_path}->zone'] = dhcp.zone
            dhcp_server_settings[f'{host_path}->ip_address'] = dhcp.ip
            dhcp_server_settings[f'{host_path}->description'] = dhcp.description

        elif (action is CFG.DEL):
            del dhcp_server_settings[f'reservations->{dhcp.mac.replace(":", "")}']

        dnx.write_configuration(dhcp_server_settings.expanded_user_data)

def remove_dhcp_lease(ip_addr: str) -> Optional[ValidationError]:
    with ConfigurationManager('dhcp_server', cfg_type='global') as dnx:
        dhcp_leases: ConfigChain = dnx.load_configuration()

        try:
            del dhcp_leases[f'leases->{ip_addr}']
        except KeyError:
            return ValidationError(INVALID_FORM)

        dnx.write_configuration(dhcp_leases.expanded_user_data)
