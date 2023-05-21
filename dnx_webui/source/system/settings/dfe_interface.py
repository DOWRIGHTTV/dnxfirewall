#!/usr/bin/python3

from __future__ import annotations

import dnx_iptools.interface_ops as interface

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_constants import HOME_DIR
from dnx_gentools.def_enums import CFG, DATA, INTF
from dnx_gentools.file_operations import config, ConfigurationManager
from dnx_gentools.file_operations import load_file, load_data, load_configuration, json_to_yaml

from dnx_control.control.ctl_action import system_action

from dnx_iptools.interface_ops import get_configurable_interfaces, get_ip_network, get_mac_string, get_ipaddress, get_netmask
from dnx_iptools.cprotocol_tools import itoip, default_route

from source.web_interfaces import StandardWebPage

__all__ = ('WebPage', 'get_interfaces_overview')

_IP_DISABLED = True

class WebPage(StandardWebPage):
    '''
    available methods: load, update
    '''
    @staticmethod
    def load(_: Form) -> dict[str, Any]:
        # system_settings: ConfigChain = load_configuration('system', cfg_type='global')
        #
        # wan_intf = 'interfaces->builtin->std_1'
        #
        # wan_id: str = system_settings[f'{wan_intf}->id']
        # wan_state: int = system_settings[f'{wan_intf}->state']
        # default_mac:    str = system_settings[f'{wan_intf}->default_mac']
        # configured_mac: str = system_settings[f'{wan_intf}->default_mac']
        #
        # try:
        #     ip_addr = itoip(interface.get_ipaddress(interface=wan_id))
        # except OverflowError:
        #     ip_addr = 'NOT SET'
        #
        # try:
        #     netmask = itoip(interface.get_netmask(interface=wan_id))
        # except OverflowError:
        #     netmask = 'NOT SET'

        return {
            # 'mac': {
            #     'default': default_mac,
            #     'current': configured_mac if configured_mac else default_mac
            # },
            # 'ip': {
            #     'state': wan_state,
            #     'ip_address': ip_addr,
            #     'netmask': netmask,
            #     'default_gateway': itoip(default_route())
            # },
            'overview': get_interfaces_overview(),
            'configuration': get_interfaces_configuration()
        }

    @staticmethod
    def update(form: Form) -> tuple[int, str]:
        print(form)

        if ('wan_state_update' in form):

            wan_state = form.get('wan_state_update', DATA.MISSING)
            if (wan_state is DATA.MISSING):
                return 1, INVALID_FORM

            try:
                wan_state = INTF(convert_int(wan_state))
            except (ValidationError, KeyError):
                return 2, INVALID_FORM

            else:
                set_wan_interface(wan_state)

        elif ('wan_ip_update' in form):
            wan_ip_settings = config(**{
                'ip': form.get('wan_ip', DATA.MISSING),
                'cidr': form.get('wan_cidr', DATA.MISSING),
                'dfg': form.get('wan_dfg', DATA.MISSING)
            })

            if (DATA.MISSING in wan_ip_settings.values()):
                return 3, INVALID_FORM

            try:
                ip_address(wan_ip_settings.ip)
                cidr(wan_ip_settings.cidr)
                ip_address(wan_ip_settings.dfg)
            except ValidationError as ve:
                return 4, ve.message

            set_wan_ip(wan_ip_settings)

        elif (_IP_DISABLED):
            return 98, 'wan interface configuration currently disabled for system rework.'

        elif ('wan_mac_update' in form):

            mac_addr = form.get('ud_wan_mac', DATA.MISSING)
            if (mac_addr is DATA.MISSING):
                return 5, INVALID_FORM

            try:
                mac_address(mac_addr)
            except ValidationError as ve:
                return 6, ve.message
            else:
                set_wan_mac(CFG.ADD, mac_address=mac_address)

        elif ('wan_mac_restore' in form):
            set_wan_mac(CFG.DEL)

        else:
            return 99, INVALID_FORM

        return NO_STANDARD_ERROR

# ==============
# CONFIGURATION
# ==============
# TODO: TEST THIS
def set_wan_interface(intf_type: INTF = INTF.DHCP):
    '''Change wan interface state between static or dhcp.

    1. Configure interface type
    2. Create netplan config from template
    3. Move file to /etc/netplan

    This does not configure an ip address of the interface when setting to static. see: set_wan_ip()
    '''
    # changing dhcp status of wan interface in config file.
    with ConfigurationManager('system') as dnx:
        dnx_settings: ConfigChain = dnx.load_configuration()

        wan_id: str = dnx_settings['interfaces->builtin->wan->id']

        # template used to generate yaml file with user configured fields
        intf_template: dict = load_data('interfaces.cfg', filepath='dnx_profile/interfaces')

        # for static dhcp4 and dhcp_overrides keys are removed and creating an empty list for the addresses.
        # NOTE: the ip configuration will unlock after the switch and can then be updated
        if (intf_type is INTF.STATIC):
            wan_intf: dict = intf_template['network']['ethernets'][wan_id]

            wan_intf.pop('dhcp4')
            wan_intf.pop('dhcp4-overrides')

            # initializing static, but not configuring an ip address
            wan_intf['addresses'] = '[]'

        _configure_netplan(intf_template)

        # TODO: writing state change after file has been replaced because any errors prior to this will prevent
        #  configuration from taking effect.
        #  the trade off is that the process could replace the file, but not set the wan state (configuration mismatch)
        dnx_settings['interfaces->builtin->wan->state'] = intf_type
        dnx.write_configuration(dnx_settings.expanded_user_data)

        system_action(module='webui', command='netplan apply', args='')

def get_interfaces_configuration() -> dict:
    '''loading installed system interfaces, then returning dict with "builtin" and "extended" separated.
    '''
    builtin_intfs, extended_intfs = get_configurable_interfaces()

    system_interfaces = {'builtin': [], 'extended': []}
    for intf_id, intf in builtin_intfs.items():
        mac_addr = get_mac_string(interface=intf_id)
        ip_addr = itoip(get_ipaddress(interface=intf_id))
        netmask = itoip(get_netmask(interface=intf_id))
        dfg = itoip(default_route())

        dhcp_state = 'on' if intf['dhcp'] else 'off'

        system_interfaces['builtin'].append([
            INTF.BUILTIN, intf_id, mac_addr, 'untrust', intf['name'], dhcp_state, ip_addr, netmask, dfg
        ])

    for intf_id, intf in extended_intfs.items():
        mac_addr = get_mac_string(interface=intf['id'])
        ip_addr = itoip(get_ipaddress(interface=intf['id']))
        netmask = itoip(get_netmask(interface=intf['id']))
        dfg = itoip(default_route())

        dhcp_state = 'on' if intf['dhcp'] else 'off'

        system_interfaces['extended'].append([
            INTF.EXTENDED, intf_id, mac_addr, 'zone', intf['name'], dhcp_state, ip_addr, netmask, dfg
        ])

    return system_interfaces

def get_interfaces_overview() -> dict:

    builtin_intfs, extended_intfs = get_configurable_interfaces()

    zones: dict = load_configuration('system', cfg_type='global').get_dict('zones')
    configured_zones = {**zones['builtin'], **zones['extended']}

    # intf values -> [ ["general info"], ["transmit"], ["receive"] ]
    system_interfaces = {'builtin': [], 'extended': [], 'unassociated': []}

    # skipping identifier column names
    for interface in load_file('/proc/net/dev', start=2):

        data = interface.split()
        intf_id = data[0][:-1]  # removing the ":"

        intf: Optional[dict[str, str]]

        if intf := builtin_intfs.get(intf_id, None):

            zone_id = str(intf['zone'])  # zone id is natively an integer on the backend. this converts for FE use.

            zone_name = configured_zones[zone_id][0]
            ip_addr = get_ip_network(interface=intf_id)

            system_interfaces['builtin'].append([
                [intf_id, intf['name'], zone_name, ip_addr], [data[1], data[2]], [data[9], data[10]]
            ])

        elif intf := extended_intfs.get(intf_id, None):

            zone_name = configured_zones[intf['zone']][0]
            ip_addr = get_ip_network(interface=intf_id)

            system_interfaces['extended'].append([
                [intf_id, intf['name'], zone_name, ip_addr], [data[1], data[2]], [data[9], data[10]]
            ])

        # functional else with loopback filter
        elif (intf_id != 'lo'):
            system_interfaces['unassociated'].append([[intf_id, 'none', 'none', 'none'], [data[1], data[2]], [data[9], data[10]]])

    return system_interfaces

# TODO: fix this later
# def set_wan_mac(action: CFG, mac_address: Optional[str] = None):
#     with ConfigurationManager('system') as dnx:
#         dnx_settings = dnx.load_configuration()
#
#         wan_settings = dnx_settings['interfaces']['builtin']['wan']
#
#         new_mac = mac_address if action is CFG.ADD else wan_settings['default_mac']
#
#         wan_int = wan_settings['id']
#         # iterating over the necessary command args, then sending over local socket
#         # for control service to issue the commands
#         args = [f'{wan_int} down', f'{wan_int} hw ether {new_mac}', f'{wan_int} up']
#         for arg in args:
#
#             system_action(module='webui', command='ifconfig', args=arg)
#
#         wan_settings['configured_mac'] = mac_address
#
#         dnx.write_configuration(dnx_settings)

def set_wan_ip(wan_settings: config) -> None:
    '''
    Modify configured WAN interface IP address.

    1. Loads configured DNS servers
    2. Loads wan interface idity
    3. Create netplan config from template
    4. Move file to /etc/netplan
    '''
    dnx_settings: ConfigChain = load_configuration('system', cfg_type='global')

    wan_id: str = dnx_settings['interfaces->builtin->wan->id']

    intf_template: dict = load_data('interfaces.cfg', filepath='dnx_profile/interfaces')

    # removing dhcp4 and dhcp_overrides keys, then adding ip address value
    wan_intf: dict = intf_template['network']['ethernets'][wan_id]

    wan_intf.pop('dhcp4')
    wan_intf.pop('dhcp4-overrides')

    wan_intf['addresses'] = f'[{wan_settings.ip}/{wan_settings.cidr}]'
    wan_intf['gateway4']  = f'{wan_settings.dfg}'

    _configure_netplan(intf_template)

    system_action(module='webui', command='netplan apply')

def _configure_netplan(intf_config: dict) -> None:
    '''writes modified template to file and moves it to /etc/netplan using os.replace.

        note: this does NOT run "netplan apply"
    '''
    # grabbing configured dns servers
    dns_server_settings: ConfigChain = load_configuration('dns_server', cfg_type='global')

    dns1: str = dns_server_settings['resolvers->primary->ip_address']
    dns2: str = dns_server_settings['resolvers->secondary->ip_address']

    # creating YAML string and applying loaded server values
    converted_config = json_to_yaml(intf_config)
    converted_config = converted_config.replace('_PRIMARY__SECONDARY_', f'{dns1},{dns2}')

    # writing YAML to interface folder to be used as swap
    with open(f'{HOME_DIR}/dnx_profile/interfaces/01-dnx-interfaces.yaml', 'w') as dnx_intfs:
        dnx_intfs.write(converted_config)

    # sending replace command to system control service
    cmd_args = [f'{HOME_DIR}/dnx_profile/interfaces/01-dnx-interfaces.yaml', '/etc/netplan/01-dnx-interfaces.yaml']
    system_action(module='webui', command='os.replace', args=cmd_args)
