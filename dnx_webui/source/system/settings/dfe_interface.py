#!/usr/bin/python3

from __future__ import annotations

import dnx_iptools.interface_ops as interface

from source.web_typing import *
from source.web_validate import ValidationError, convert_int, mac_address, ip_address, cidr

from dnx_gentools.def_constants import HOME_DIR, INVALID_FORM
from dnx_gentools.def_enums import CFG, DATA, INTF
from dnx_gentools.file_operations import load_data, load_configuration, config, ConfigurationManager, json_to_yaml

from dnx_system.sys_action import system_action

from dnx_iptools.cprotocol_tools import itoip, default_route


_IP_DISABLED = True

def load_page(_: Form) -> dict[str, Any]:
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
            'default_gateway': itoip(default_route())
        }
    }

def update_page(form: Form) -> str:
    if ('wan_state_update' in form):
        wan_state = form.get('wan_state_update', DATA.MISSING)
        if (wan_state is DATA.MISSING):
            return INVALID_FORM

        try:
            wan_state = INTF(convert_int(wan_state))
        except (ValidationError, KeyError):
            return INVALID_FORM

        else:
            set_wan_interface(wan_state)

    elif ('wan_ip_update' in form):
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
            return ve.message

        set_wan_ip(wan_ip_settings)

    elif (_IP_DISABLED):
        return 'wan interface configuration currently disabled for system rework.'

    elif ('wan_mac_update' in form):
        mac_addr = form.get('ud_wan_mac', DATA.MISSING)
        if (mac_addr is DATA.MISSING):
            return INVALID_FORM

        try:
            mac_address(mac_addr)
        except ValidationError as ve:
            return ve.message
        else:
            set_wan_mac(CFG.ADD, mac_address=mac_address)

    elif ('wan_mac_restore' in form):
        set_wan_mac(CFG.DEL)

    else:
        return INVALID_FORM

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

        wan_ident: str = dnx_settings['interfaces->builtins->wan->ident']

        # template used to generate yaml file with user configured fields
        intf_template: dict = load_data('intf_config_template.cfg', filepath='dnx_system/interfaces')

        # for static dhcp4 and dhcp_overrides keys are removed and creating an empty list for the addresses.
        # NOTE: the ip configuration will unlock after the switch and can then be updated
        if (intf_type is INTF.STATIC):
            wan_intf: dict = intf_template['network']['ethernets'][wan_ident]

            wan_intf.pop('dhcp4')
            wan_intf.pop('dhcp4-overrides')

            # initializing static, but not configuring an ip address
            wan_intf['addresses'] = '[]'

        # grabbing configured dns servers
        dns_server_settings: ConfigChain = load_configuration('dns_server')

        dns1: str = dns_server_settings['resolvers->primary->ip_address']
        dns2: str = dns_server_settings['resolvers->secondary->ip_address']

        # dns server replacement in template required for static or dhcp
        converted_config = json_to_yaml(intf_template)
        converted_config = converted_config.replace('_PRIMARY__SECONDARY_', f'{dns1},{dns2}')

        # writing file into dnx_system folder due to limited permissions by the front end.
        # netplan and the specific mv args operate under sudo/no-pass to get the config loaded.
        with open(f'{HOME_DIR}/dnx_system/interfaces/01-dnx-interfaces.yaml', 'w') as dnx_intfs:
            dnx_intfs.write(converted_config)

        cmd_args = ['{HOME_DIR}/dnx_system/interfaces/01-dnx-interfaces.yaml', '/etc/netplan/01-dnx-interfaces.yaml']
        system_action(module='webui', command='os.replace', args=cmd_args)

        # TODO: writing state change after file has been replaced because any errors prior to this will prevent
        #  configuration from taking effect.
        #  the trade off is that the process could replace the file, but not set the wan state (configuration mismatch)
        dnx_settings['interfaces->builtins->wan->state'] = intf_type
        dnx.write_configuration(dnx_settings.expanded_user_data)

        system_action(module='webui', command='netplan apply', args='')

# TODO: fix this later
# def set_wan_mac(action: CFG, mac_address: Optional[str] = None):
#     with ConfigurationManager('system') as dnx:
#         dnx_settings = dnx.load_configuration()
#
#         wan_settings = dnx_settings['interfaces']['builtins']['wan']
#
#         new_mac = mac_address if action is CFG.ADD else wan_settings['default_mac']
#
#         wan_int = wan_settings['ident']
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
    2. Loads wan interface identity
    3. Create netplan config from template
    4. Move file to /etc/netplan
    '''
    dnx_settings: ConfigChain = load_configuration('system')

    wan_ident: str = dnx_settings['interfaces->builtins->wan->ident']

    # grabbing configured dns servers
    dns_server_settings: ConfigChain = load_configuration('dns_server')

    dns1: str = dns_server_settings['resolvers->primary->ip_address']
    dns2: str = dns_server_settings['resolvers->secondary->ip_address']

    intf_template: dict = load_data('intf_config_template.cfg', filepath='dnx_system/interfaces')

    # removing dhcp4 and dhcp_overrides keys, then adding ip address value
    wan_intf: dict = intf_template['network']['ethernets'][wan_ident]

    wan_intf.pop('dhcp4')
    wan_intf.pop('dhcp4-overrides')

    wan_intf['addresses'] = f'[{wan_settings.ip}/{wan_settings.cidr}]'
    wan_intf['gateway4']  = f'{wan_settings.dfg}'

    converted_config = json_to_yaml(intf_template)
    converted_config = converted_config.replace('_PRIMARY__SECONDARY_', f'{dns1},{dns2}')

    # writing file into dnx_system folder due to limited permissions by the front end.
    # netplan and the specific mv args are configured as sudo/no-pass to get the config to netplan.
    # this will apply system settings without a restart.
    with open(f'{HOME_DIR}/dnx_system/interfaces/01-dnx-interfaces.yaml', 'w') as dnx_intfs:
        dnx_intfs.write(converted_config)

    cmd_args = [f'{HOME_DIR}/dnx_system/interfaces/01-dnx-interfaces.yaml', '/etc/netplan/01-dnx-interfaces.yaml']
    system_action(module='webui', command='os.replace', args=cmd_args)
    system_action(module='webui', command='netplan apply')