#!/usr/bin/python3


import os, sys
import collections
import re
import json
import time

from types import SimpleNamespace
from subprocess import run, CalledProcessError

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_iptools.dnx_interface as interface

from dnx_configure.dnx_constants import CFG, INTF, INVALID_FORM, shell, fast_time, str_join
from dnx_configure.dnx_file_operations import load_configuration, ConfigurationManager, json_to_yaml
from dnx_configure.dnx_exceptions import ValidationError
from dnx_system.sys_main import system_action
from dnx_configure.dnx_system_info import System, Services, Interface
from dnx_frontend.dfe_dnx_authentication import Authentication
from dnx_logging.log_main import LogHandler as Log

# NOTE: this will allow the config manager to reference the Log class without an import. (cyclical import error)
ConfigurationManager.set_log_reference(Log)

def set_default_mac_flag():
    with ConfigurationManager('config') as dnx:
        dnx_settings = dnx.load_configuration()

        wan_settings = dnx_settings['interfaces']['wan']
        if (not wan_settings['mac_set']):
            wan_settings.update({
                'default_mac': Interface.mac_address(interface=wan_settings['ident']),
                'mac_set': True
            })

        dnx.write_configuration(dnx_settings)

def set_wan_mac(action, mac_address=None):
    with ConfigurationManager('config') as dnx:
        dnx_settings = dnx.load_configuration()

        wan_settings = dnx_settings['interfaces']['wan']

        new_mac = mac_address if action is CFG.ADD else wan_settings['default_mac']

        wan_int = wan_settings['ident']
        # iterating over the necessary command args, then sending over local socket
        # for control service to issue the commands
        args = [f'{wan_int} down', f'{wan_int} hw ether {new_mac}', f'{wan_int} up']
        for arg in args:

            system_action(module='webui', command='ifconfig', args=arg)

        wan_settings['configured_mac'] = mac_address

        dnx.write_configuration(dnx_settings)

def set_dhcp_reservation(dhcp_settings, action):
    with ConfigurationManager('dhcp_server') as dnx:
        dhcp_server_settings = dnx.load_configuration()

        leases = dhcp_server_settings['leases']
        reservations = dhcp_server_settings['reservations']
        reserved_ips = set([info['ip_address'] for info in reservations.values()])

        if (action is CFG.ADD):

            # preventing reservations being created for ips with an active dhcp lease
            if (dhcp_settings['ip'] in leases):
                raise ValidationError(
                    f'There is an active lease with {dhcp_settings["ip"]}. Clear the lease and try again.'
                )

            # ensuring mac address and ip address are unique
            if (dhcp_settings['mac'] in reservations or dhcp_settings['ip'] in reserved_ips):
                raise ValidationError(f'{dhcp_settings["ip"]} is already reserved.')

            reservations.update({
                dhcp_settings['mac']: {
                    'zone': dhcp_settings['zone'],
                    'ip_address': dhcp_settings['ip'],
                    'description': dhcp_settings['description']
                }
            })

        elif (action is CFG.DEL):
            reservations.pop(dhcp_settings['mac'], None)

        dnx.write_configuration(dhcp_server_settings)

def set_dhcp_settings(dhcp_settings):
    with ConfigurationManager('dhcp_server') as dnx:
        dhcp_server_settings = dnx.load_configuration()

        interface = dhcp_settings.pop('interface')

        dhcp_server_settings['interfaces'][interface].update(dhcp_settings)

        dnx.write_configuration(dhcp_server_settings)

def remove_dhcp_lease(ip_addr):
    with ConfigurationManager('dhcp_server') as dnx:
        dhcp_leases = dnx.load_configuration()

        leases = dhcp_leases['leases']

        if not leases.pop(ip_addr, None):
            raise ValidationError(INVALID_FORM)

        dnx.write_configuration(dhcp_leases)


def set_domain_categories(en_cats, *, ruleset):
    with ConfigurationManager('dns_proxy') as dnx:
        dns_proxy_categories = dnx.load_configuration()

        categories = dns_proxy_categories['categories']
        if (ruleset in ['default', 'user_defined']):
            domain_cats = categories[ruleset]

        for cat, settings in domain_cats.items():
            if (cat in ['malicious', 'cryptominer']): continue

            settings['enabled'] = True if cat in en_cats else False

        dnx.write_configuration(dns_proxy_categories)

def set_domain_category_keywords(en_keywords):
    with ConfigurationManager('dns_proxy') as dnx:
        dns_proxy_categories = dnx.load_configuration()

        domain_cats = dns_proxy_categories['categories']['default']
        for cat, settings in domain_cats.items():
            settings['keyword'] = True if cat in en_keywords else False

        dnx.write_configuration(dns_proxy_categories)

def set_logging(log_settings):
    with ConfigurationManager('logging_client') as dnx:
        logging_settings = dnx.load_configuration()

        logging_settings['logging'] = log_settings

        dnx.write_configuration(logging_settings)

# NOTE: this may be incorrect for DHCP wan configuration. it appears if wan is dhcp
# only the dnx config file will change, but the system one will not be changed
# CHANGING DNS SERVERS MIGHT REQUIRE WAN RESTART WHICH WOULD. INVESTIGATE.
def set_dns_servers(dns_server_info):
    field = {1: 'primary', 2: 'secondary'}

    with ConfigurationManager('dns_server') as dnx:
        dns_server_settings = dnx.load_configuration()

        public_resolvers = dns_server_settings['dns_server']['resolvers']

        for i, (server_name, ip_address) in enumerate(dns_server_info.items(), 1):
            if (not server_name and ip_address):
                continue

            public_resolvers[field[i]].update({
                'name': server_name,
                'ip_address': ip_address
            })

        dnx.write_configuration(dns_server_settings)

    wan_information = load_configuration('config')
    interface = wan_information['interfaces']
    wan_dhcp = interface['wan']['dhcp']
    wan_int = interface['wan']['ident']
    if (not wan_dhcp):
        wan_ip = interface.get_ip_address(wan_int)

        wan_dfg = Interface.default_gateway(wan_int)
        cidr = System.standard_to_cidr(wan_netmask)

        # TODO: convert this to new module
        wan_netmask = Interface.netmask(wan_int)

        set_wan_interface({
            'ip_address': wan_ip, 'cidr': cidr, 'default_gateway': wan_dfg
        })

def update_dns_record(dns_record_name, action, dns_record_ip=None):
    with ConfigurationManager('dns_server') as dnx:
        dns_records = dnx.load_configuration()

        record = dns_records['dns_server']['records']
        if (action is CFG.ADD):
            record[dns_record_name] = dns_record_ip

        elif (action is CFG.DEL):
            record.pop(dns_record_name, None)

        dnx.write_configuration(dns_records)

def configure_user_account(account_info, action):
    acct = SimpleNamespace(**account_info)
    with ConfigurationManager('logins', file_path='/dnx_frontend/data') as dnx:
        accounts = dnx.load_configuration()

        userlist = accounts['users']
        if (action is CFG.DEL):
            userlist.pop(acct.username)

        elif (action is CFG.ADD and acct.username not in userlist):
            Account = Authentication()
            hexpass = Account.hash_password(acct.username, acct.password)
            userlist.update({
                acct.username: {
                    'password': hexpass,
                    'role': acct.role
                }
            })
        else:
            raise ValidationError('User account already exists.')

        dnx.write_configuration(accounts)

def set_proxy_exception(exception_settings, *, ruleset):
    with ConfigurationManager(ruleset) as dnx:
        exceptions_list = dnx.load_configuration()

        exceptions = exceptions_list['exception']
        if (exception_settings['action'] is CFG.ADD):
            exceptions[exception_settings['domain']]['reason'] = exception_settings['reason']

        elif (exception_settings['action'] is CFG.DEL):
            exceptions.pop(exception_settings['domain'])

        dnx.write_configuration(exceptions_list)

# Creating/Deleting User Defined Category / will be disabled by default#
def update_custom_category(category, *, action):
    with ConfigurationManager('dns_proxy') as dnx:
        custom_category_lists = dnx.load_configuration()

        ud_cats = custom_category_lists['categories']['user_defined']
        if (action is CFG.DEL and category != 'enabled'):
            ud_cats.pop(category, None)

        elif (action is CFG.ADD):
            if (len(ud_cats) >= 6):
                raise ValidationError('Only support for maximum of 6 custom categories.')

            elif (category in ud_cats):
                raise ValidationError('Custom category already exists.')

            ud_cats[category] = {'enabled': False}

        dnx.write_configuration(custom_category_lists)

# Adding/Removing domain from User Defined Category #
def update_custom_category_domain(category, domain, reason=None, *, action):
    with ConfigurationManager('dns_proxy') as dnx:
        custom_category_domains = dnx.load_configuration()

        ud_cats = custom_category_domains['categories']['user_defined']
        if (action is CFG.DEL and category != 'enabled'):
            ud_cats[category].pop(domain, None)

        elif (action is CFG.ADD):
            if (domain in ud_cats[category]):
                raise ValidationError('Domain rule already exists for this category.')
            else:
                ud_cats[category][domain] = reason

        dnx.write_configuration(custom_category_domains)

# adds a time based rule to whitelist/blacklist
def add_proxy_domain(whitelist_settings, *, ruleset):
    input_time  = int(fast_time())
    expire_time = input_time + whitelist_settings['timer'] * 60

    with ConfigurationManager(ruleset) as dnx:
        domain_list = dnx.load_configuration()

        domain_list['domain'].update({
            whitelist_settings['domain']: {
                'time': input_time,
                'rule_length': whitelist_settings['timer'],
                'expire': expire_time
            }
        })

        dnx.write_configuration(domain_list)

def del_proxy_domain(domain, *, ruleset):
    with ConfigurationManager(ruleset) as dnx:
        domain_list = dnx.load_configuration()

        result = domain_list['domain'].pop(domain, None)

        # if domain was not present (likely removed in another process), there is
        # no need to write file to disk
        if (result is not None):

            dnx.write_configuration(domain_list)

def set_domain_tlds(update_tlds):
    with ConfigurationManager('dns_proxy') as dnx:
        proxy_settings = dnx.load_configuration()

        tld_list = proxy_settings['tlds']
        for entry in tld_list:
            tld_list[entry] = True if entry in update_tlds else False


        dnx.write_configuration(proxy_settings)

def add_proxy_ip_whitelist(whitelist_settings):
    with ConfigurationManager('whitelist') as dnx:
        whitelist = dnx.load_configuration()

        whitelist['ip_whitelist'][whitelist_settings['ip']] = {
            'user': whitelist_settings['user'],
            'type': whitelist_settings['type']
        }

        dnx.write_configuration(whitelist)

def del_proxy_ip_whitelist(whitelist_ip):
    with ConfigurationManager('whitelist') as dnx:
        whitelist = dnx.load_configuration()

        result = whitelist['ip_whitelist'].pop(whitelist_ip, None)

        # if ip was not present (likely removed in another process), there is
        # no need to write file to disk
        if (result is not None):

            dnx.write_configuration(whitelist)

def update_ips_ip_whitelist(whitelist_ip, whitelist_name, *, action):
    with ConfigurationManager('ips') as dnx:
        ips_settings = dnx.load_configuration()

        ips_whitelist = ips_settings['ip_whitelist']
        if (action is CFG.ADD):
            ips_whitelist[whitelist_ip] = whitelist_name

        elif (action is CFG.DEL):
            result = ips_whitelist.pop(whitelist_ip, None)

            if (result is None): return

        dnx.write_configuration(ips_settings)

def update_ips_dns_whitelist(action):
    with ConfigurationManager('ips') as dnx:
        ips_settings = dnx.load_configuration()

        ips_settings['dns_servers'] = action

        dnx.write_configuration(ips_settings)

def update_ip_proxy_settings(category_settings, *, ruleset='categories'):
    with ConfigurationManager('ip_proxy') as dnx:
        ip_proxy_settings = dnx.load_configuration()

        category_lists = ip_proxy_settings[ruleset]
        for category in category_settings:
            category, direction = category[:-2], int(category[-1])

            category_lists[category] = direction

        dnx.write_configuration(ip_proxy_settings)

def set_dns_keywords(action):
    with ConfigurationManager('dns_proxy') as dnx:
        keyword_settings = dnx.load_configuration()

        keyword_settings['keyword']['enabled'] = action

        dnx.write_configuration(keyword_settings)

def update_system_time_offset(new_offset_settings):
    with ConfigurationManager('logging_client') as dnx:
        offset_settings = dnx.load_configuration()

        if (new_offset_settings['time'] == 0):
            new_offset_settings['direction'] = '+'

        offset = offset_settings['time_offset']
        offset.update({
            'direction': new_offset_settings['direction'],
            'amount': new_offset_settings['time']
        })

        dnx.write_configuration(offset_settings)

def modify_management_access(fields):
    with ConfigurationManager('config') as dnx:
        mgmt_settings = dnx.load_configuration()

        mgmt_settings['mgmt_access'][fields.zone][fields.service] = fields.action

        dnx.write_configuration(mgmt_settings)

def set_syslog_settings(syslog_settings):
    with ConfigurationManager('syslog_client') as dnx:
        stored_syslog_settings = dnx.load_configuration()

        syslog = stored_syslog_settings
        tls_settings = syslog['tls']
        tcp_settings = syslog['tcp']

        for option in tls_settings:
            if (option in syslog_settings['tls'] and option != 'retry'):
                tls_settings[option] = True

            elif (option not in syslog_settings['tls']):
                tls_settings[option] = False

        for protocol in ['tcp', 'udp']:
            fallback = f'{protocol}_fallback'
            if (fallback in syslog_settings['fallback']):
                syslog[protocol]['fallback'] = True
            else:
                syslog[protocol]['fallback'] = False

        syslog['protocol'] = 6 if 'syslog_protocol' in syslog_settings else 17
        syslog['enabled'] = True if 'syslog_enabled' in syslog_settings else False

        tls_settings['retry'] = int(syslog_settings['tls_retry']) * 60
        tcp_settings['retry'] = int(syslog_settings['tcp_retry']) * 60

        dnx.write_configuration(stored_syslog_settings)

def set_syslog_servers(syslog_servers):
    with ConfigurationManager('syslog_client') as dnx:
        syslog_settings = dnx.load_configuration()

        servers = syslog_settings['servers']
        for server, server_info in syslog_servers.items():
            if (not server_info['ip_address']): continue

            servers.update({
                server: {
                    'ip_address': server_info['ip_address'],
                    'port': int(server_info['port'])
                }
            })

        dnx.write_configuration(syslog_settings)

# NOTE: why is this returning a value? is this doing some validation checking?
def remove_syslog_server(syslog_server_number):
    with ConfigurationManager('syslog_client') as dnx:
        syslog_settings = dnx.load_configuration()

        servers = syslog_settings['servers']
        result = servers.pop(f'Server{syslog_server_number}', False)
        if (result and 'server2' in servers):
            servers['server1'] = servers.pop('server2')

        dnx.write_configuration(syslog_settings)

    return result

def update_ip_restriction_settings(tr_settings):
    with ConfigurationManager('ip_proxy') as dnx:
        ip_proxy_settings = dnx.load_configuration()

        tr_settings['hour'] += 12 if tr_settings['suffix'] == 'PM' else tr_settings['hour']

        start_time = f'{tr_settings["hour"]}:{tr_settings["minutes"]}'

        tlen_hour = tr_settings['length_hour']
        min_fraction = str(tr_settings['length_minutes']/60).strip('0.')
        res_length = f'{tlen_hour}.{min_fraction}'
        res_length = int(float(res_length) * 3600)

        ip_proxy_settings['time_restriction'].update({
            'start': start_time,
            'length': res_length,
            'enabled': tr_settings['enabled']
        })

        dnx.write_configuration(ip_proxy_settings)

def set_dns_cache_clear_flag(clear_dns_cache):
    with ConfigurationManager('dns_server') as dnx:
        dns_server_settings = dnx.load_configuration()

        dns_cache_flags = dns_server_settings['dns_server']['cache']
        for flag, setting in clear_dns_cache.items():
            if (setting):
                dns_cache_flags[flag] = True

        dnx.write_configuration(dns_server_settings)

def set_ips_ddos(action):
    with ConfigurationManager('ips') as dnx:
        ips_settings = dnx.load_configuration()

        ips_settings['ddos']['enabled'] = action

        dnx.write_configuration(ips_settings)

def set_ips_portscan(portscan_settings):
    with ConfigurationManager('ips') as dnx:
        ips_settings = dnx.load_configuration()

        ps_settings = ips_settings['port_scan']

        ps_settings['enabled'] = True if 'enabled' in portscan_settings else False
        ps_settings['reject']  = True if 'reject' in portscan_settings else False

        dnx.write_configuration(ips_settings)

def set_ips_general_settings(pb_length, ids_mode):
    with ConfigurationManager('ips') as dnx:
        ips_settings = dnx.load_configuration()

        ips_settings['passive_block_ttl'] = pb_length
        ips_settings['ids_mode'] = ids_mode

        dnx.write_configuration(ips_settings)

def set_ips_ddos_limits(ddos_limits):
    with ConfigurationManager('ips') as dnx:
        ips_settings = dnx.load_configuration()

        limits = ips_settings['ddos']['limits']['source']
        for protocol, limit in ddos_limits.items():
            limits[protocol] = limit

        dnx.write_configuration(ips_settings)

def set_wan_interface(intf_type=INTF.DHCP):
    '''Change wan interface state between static or dhcp.

    1. Configure interface type
    2. Create netplan config from template
    3. Move file to /etc/netplan

    This does not configure an ip address of the interface when setting to static. see: set_wan_ip()
    '''

    # changing dhcp status of wan interface in config file.
    with ConfigurationManager('config') as dnx:
        interface_settings = dnx.load_configuration()

        wan = interface_settings['interfaces']['wan']

        wan['state'] = intf_type

        dnx.write_configuration(interface_settings)

        # template used to generate yaml file with user configured fields
        intf_template = load_configuration('intf_config', filepath='dnx_system/interfaces')

        # setting for static. removing dhcp4 and dhcp_overrides keys, then adding addresses with empty list
        # NOTE: the ip configuration will unlock after the switch and can then be updated
        if (intf_type is INTF.STATIC):
            wan_intf = intf_template['network']['ethernets'][wan['ident']]

            wan_intf.pop('dhcp4')
            wan_intf.pop('dhcp4-overrides')

            # initializing static, but not configuring an ip address
            wan_intf['addresses'] = '[]'

        # grabbing configured dns servers
        dns_server_settings = load_configuration('dns_server')['resolvers']

        dns1 = dns_server_settings['primary']['ip_address']
        dns2 = dns_server_settings['secondary']['ip_address']

        # dns server replacement in template required for static or dhcp
        converted_config = json_to_yaml(intf_template)
        converted_config = converted_config.replace('_PRIMARY__SECONDARY_', f'{dns1},{dns2}')

        # writing file into dnx_system folder due to limited permissions by the front end. netplan and the specific
        # mv args are configured as sudo/no-pass to get the config to netplan and it applied without a restart.
        with open(f'{HOME_DIR}/dnx_system/interfaces/01-dnx-interfaces.yaml', 'w') as dnx_intfs:
            dnx_intfs.write(converted_config)

        cmd_args = ['{HOME_DIR}/dnx_system/interfaces/01-dnx-interfaces.yaml', '/etc/netplan/01-dnx-interfaces.yaml']
        system_action(module='webui', command='os.replace', args=cmd_args)
        system_action(module='webui', command='netplan apply', args='')

def set_wan_ip(wan_ip_settings):
    '''Modify configured WAN interface IP address.

    1. Loads configured DNS servers
    2. Loads wan interface identity
    3. Create netplan config from template
    4. Move file to /etc/netplan
    '''

    wan_int = load_configuration('config')['interfaces']['wan']['ident']

    # grabbing configured dns servers
    dns_server_settings = load_configuration('dns_server')['resolvers']

    dns1 = dns_server_settings['primary']['ip_address']
    dns2 = dns_server_settings['secondary']['ip_address']

    intf_template = load_configuration('intf_config', filepath='dnx_system/interfaces')

    # removing dhcp4 and dhcp_overrides keys, then adding ip address value
    wan_intf = intf_template['network']['ethernets'][wan_int]

    wan_intf.pop('dhcp4')
    wan_intf.pop('dhcp4-overrides')

    # initializing static, but not configuring an ip address
    wan_intf['addresses'] = f'[{wan_ip_settings["ip"]}/{wan_ip_settings["cidr"]}]'
    wan_intf['gateway4']  = f'{wan_ip_settings["dfg"]}'

    converted_config = json_to_yaml(intf_template)
    converted_config = converted_config.replace('_PRIMARY__SECONDARY_', f'{dns1},{dns2}')

    # writing file into dnx_system folder due to limited permissions by the front end. netplan and the specific
    # mv args are configured as sudo/no-pass to get the config to netplan and it applied without a restart.
    with open(f'{HOME_DIR}/dnx_system/interfaces/01-dnx-interfaces.yaml', 'w') as dnx_intfs:
        dnx_intfs.write(converted_config)

    cmd_args = [f'{HOME_DIR}/dnx_system/interfaces/01-dnx-interfaces.yaml', '/etc/netplan/01-dnx-interfaces.yaml']
    system_action(module='webui', command='os.replace', args=cmd_args)
    system_action(module='webui', command='netplan apply')

def add_open_wan_protocol(nat_info):
    with ConfigurationManager('ips') as dnx:
        open_protocol_settings = dnx.load_configuration()

        open_protocols = open_protocol_settings['open_protocols']

        # if dst port is present protocol is tcp/udp
        if (nat_info.dst_port):
            open_protocols[nat_info.protocol][nat_info.dst_port] = nat_info.host_port

        # will only match icmp, which is configured as a boolean value
        else:
            open_protocols[nat_info.protocol] = True

        dnx.write_configuration(open_protocol_settings)

def del_open_wan_protocol(rule_number):
    with ConfigurationManager('ips') as dnx:
        open_protocol_settings = dnx.load_configuration()

        open_protocols = open_protocol_settings['open_protocols']
        rule = run(f'sudo iptables -t nat -nL NAT {rule_number}', shell=True, capture_output=True).stdout.split()
        protocol = rule[1]
        if (protocol in ['tcp', 'udp']):
            dst_port = rule[6].split(':')[1]
            open_protocols[protocol].pop(dst_port, None)

        elif (protocol == 'icmp'):
            open_protocols[protocol] = False

        dnx.write_configuration(open_protocol_settings)

def set_dns_over_tls(dns_tls_settings):
    with ConfigurationManager('dns_server') as dnx:
        dns_server_settings = dnx.load_configuration()

        tls_settings = dns_server_settings['dns_server']['tls']
        enabled_settings = dns_tls_settings['enabled']
        if ('dns_over_tls' in enabled_settings and 'udp_fallback' not in enabled_settings):
            tls_enabled = True
            udp_fallback = False
        elif ('dns_over_tls' in enabled_settings and 'udp_fallback' in enabled_settings):
            tls_enabled = True
            udp_fallback = True
        else:
            udp_fallback = False
            tls_enabled = False

        tls_settings.update({
            'enabled': tls_enabled,
            'fallback': udp_fallback
        })

        dnx.write_configuration(dns_server_settings)
