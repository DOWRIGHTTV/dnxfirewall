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

from dnx_configure.dnx_constants import CFG, fast_time
from dnx_configure.dnx_file_operations import load_configuration, ConfigurationManager
from dnx_configure.dnx_exceptions import ValidationError
from dnx_frontend.dfe_dnx_authentication import Authentication
from dnx_configure.dnx_iptables import IPTableManager
from dnx_configure.dnx_system_info import System, Services, Interface

def set_default_mac_flag():
    with ConfigurationManager('config') as dnx:
        dnx_settings = dnx.load_configuration()

        wan_settings = dnx_settings['settings']['interface']['wan']
        if (not wan_settings['mac_set']):
            default_mac = interface.get_mac(interface=wan_settings['ident'])
            wan_settings.update({
                'default_mac': default_mac,
                'mac_set': True
            })

        dnx.write_configuration(dnx_settings)

def set_wan_mac(action, mac_address=None):
    with ConfigurationManager('config') as dnx:
        dnx_settings = dnx.load_configuration()

        wan_settings = dnx_settings['settings']['interfaces']['wan']
        default_wan_mac = wan_settings['default_mac']
        wan_int = wan_settings['ident']
        wan_mac = wan_settings['configured_mac']

        run(f'sudo ifconfig {wan_int} down', shell=True)
        if (action is CFG.ADD):
            wan_mac['configured_mac'] = mac_address
            run(f'sudo ifconfig {wan_int} hw ether {mac_address}', shell=True)

        elif (action is CFG.DEL):
            wan_mac['configured_mac'] = None
            run(f'sudo ifconfig {wan_int} hw ether {default_wan_mac}', shell=True)

        run(f'sudo ifconfig {wan_int} up', shell=True)

        dnx.write_configuration(dnx_settings)

def set_dhcp_reservation(dhcp_settings, action):
    dhcp = SimpleNamespace(**dhcp_settings)
    with ConfigurationManager('dhcp_server') as dnx:
        dhcp_reservations = dnx.load_configuration()

        modified_mac = ''.join(dhcp.mac.split(':'))

        macs = dhcp_reservations['dhcp_server']['reservations']
        if (action is CFG.ADD and modified_mac not in macs):
            macs.update({
                modified_mac: {
                    'ip_address': dhcp.ip,
                    'name': dhcp.username
                }
            })

        elif (action is CFG.DEL):
            macs.pop(modified_mac, None)

        dnx.write_configuration(dhcp_reservations)

def set_domain_categories(en_cats, *, ruleset):
    with ConfigurationManager('dns_proxy') as dnx:
        dns_proxy_categories = dnx.load_configuration()

        categories = dns_proxy_categories['dns_proxy']['categories']
        if (ruleset in ['default', 'user_defined']):
            domain_cats = categories[ruleset]

        for cat, settings in domain_cats.items():
            if (cat in ['malicious', 'cryptominer']): continue

            settings['enabled'] = True if cat in en_cats else False

        dnx.write_configuration(dns_proxy_categories)

def set_domain_category_keywords(en_keywords):
    with ConfigurationManager('dns_proxy') as dnx:
        dns_proxy_categories = dnx.load_configuration()

        domain_cats = dns_proxy_categories['dns_proxy']['categories']['default']
        for cat, settings in domain_cats.items():
            settings['keyword'] = True if cat in en_keywords else False

        dnx.write_configuration(dns_proxy_categories)

def set_logging(log_settings):
    with ConfigurationManager('logging_client') as dnx:
        logging_settings = dnx.load_configuration()

        logging_settings['logging']['logging'] = log_settings

        dnx.write_configuration(logging_settings)

# NOTE: this may be incorrect for DHCP wan configuration. it appears if wan is dhcp
# only the dnx config file will change, but the system one will not be changed
# CHANGING DNS SERVERS MIGHT REQUIRE WAN RESTART WHICH WOULD. INVESTIGATE.
def set_dns_servers(dns_server_info):
    with ConfigurationManager('dns_server') as dnx:
        dns_server_settings = dnx.load_configuration()

        dns = dns_server_settings['dns_server']['resolvers']
        for i, (server_name, ip_address) in enumerate(dns_server_info.items(), 1):
            if (server_name and ip_address):
                server = dns[f'server{i}']
                server.update({
                    'name': server_name,
                    'ip_address': ip_address
                })

        dnx.write_configuration(dns_server_settings)

    wan_information = load_configuration('config')
    interface = wan_information['settings']['interface']
    wan_dhcp = interface['wan']['dhcp']
    wan_int = interface['outside']
    if (not wan_dhcp):
        wan_ip = interface.get_ip_address(wan_int)
        wan_netmask = Interface.netmask(wan_int)
        wan_dfg = Interface.default_gateway(wan_int)

        cidr = System.standard_to_cidr(wan_netmask)

        wan_settings = {'ip_address': wan_ip, 'cidr': cidr, 'default_gateway': wan_dfg}
        set_wan_interface(wan_settings)

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
    with ConfigurationManager('logins') as dnx:
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

def set_proxy_exception(domain, action, reason=None, *, ruleset):
    with ConfigurationManager(ruleset) as dnx:
        exceptions_list = dnx.load_configuration()

        exceptions = exceptions_list[ruleset]['exception']
        if (action is CFG.ADD):
            exceptions[domain]['reason'] = reason

        elif (action is CFG.DEL):
            exceptions.pop(domain)

        dnx.write_configuration(exceptions_list)

# Creating/Deleting User Defined Category / will be disabled by default#
def update_custom_category(category, *, action):
    with ConfigurationManager('dns_proxy') as dnx:
        custom_category_lists = dnx.load_configuration()

        ud_cats = custom_category_lists['dns_proxy']['categories']['user_defined']
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

        ud_cats = custom_category_domains['dns_proxy']['categories']['user_defined']
        if (action is CFG.DEL and category != 'enabled'):
            ud_cats[category].pop(domain, None)

        elif (action is CFG.ADD):
            if (domain in ud_cats[category]):
                raise ValidationError('Domain rule already exists for this category.')
            else:
                ud_cats[category][domain] = reason

        dnx.write_configuration(custom_category_domains)

# adds a time based rule to whitelist/blacklist
def add_proxy_domain(domain, timer, *, ruleset):
    input_time  = int(fast_time())
    expire_time = input_time + timer*60

    with ConfigurationManager(ruleset) as dnx:
        domain_list = dnx.load_configuration()

        domains = domain_list[ruleset]['domain']
        domains.update({
            domain: {
                'time': input_time,
                'rule_length': timer,
                'expire': expire_time
            }
        })

        dnx.write_configuration(domain_list)

def del_proxy_domain(domain, *, ruleset):
    with ConfigurationManager(f'{ruleset}') as dnx:
        domain_list = dnx.load_configuration()

        domain_list[ruleset]['domain'].pop(domain)

        dnx.write_configuration(domain_list)

def set_domain_tlds(update_tlds):
    with ConfigurationManager('dns_proxy') as dnx:
        proxy_settings = dnx.load_configuration()

        tld_list = proxy_settings['dns_proxy']['tlds']
        for entry in tld_list:
            tld_list[entry] = True if entry in update_tlds else False


        dnx.write_configuration(proxy_settings)

def add_proxy_ip_whitelist(whitelist_ip, whitelist_settings):
    with ConfigurationManager('whitelist') as dnx:
        whitelist = dnx.load_configuration()

        ip_whitelist = whitelist['whitelist']['ip_whitelist']
        ip_whitelist[whitelist_ip] = {
            'user': whitelist_settings['user'],
            'type': whitelist_settings['type']
        }

        dnx.write_configuration(whitelist)

def del_proxy_ip_whitelist(whitelist_ip, whitelist_type):
    with ConfigurationManager('whitelist') as dnx:
        whitelist = dnx.load_configuration()

        whitelist['whitelist']['ip_whitelist'].pop(whitelist_ip)

        dnx.write_configuration(whitelist)

def update_ips_ip_whitelist(whitelist_ip, whitelist_name, action):
    with ConfigurationManager('ips') as dnx:
        ips_settings = dnx.load_configuration()

        ips_whitelist = ips_settings['ips']['whitelist']['ip_whitelist']
        if (action is CFG.ADD):
            ips_whitelist[whitelist_ip] = whitelist_name

        elif (action is CFG.DEL):
            ips_whitelist.pop(whitelist_ip)

        dnx.write_configuration(ips_settings)

def update_ips_dns_whitelist(action):
    with ConfigurationManager('ips') as dnx:
        ips_settings = dnx.load_configuration()

        ips_settings['ips']['whitelist']['dns_servers'] = action

        dnx.write_configuration(ips_settings)

def update_ip_proxy_settings(category_settings, *, ruleset='categories'):
    with ConfigurationManager('ip_proxy') as dnx:
        ip_proxy_settings = dnx.load_configuration()

        category_lists = ip_proxy_settings['ip_proxy'][ruleset]
        for category in category_settings:
            category, direction = category[:-2], int(category[-1])

            category_lists[category] = direction

        dnx.write_configuration(ip_proxy_settings)

def set_dns_keywords(action):
    with ConfigurationManager('dns_proxy') as dnx:
        keyword_settings = dnx.load_configuration()

        keyword_settings['dns_proxy']['keyword']['enabled'] = action

        dnx.write_configuration(keyword_settings)

def update_system_time_offset(new_offset_settings):
    with ConfigurationManager('logging_client') as dnx:
        offset_settings = dnx.load_configuration()

        if (new_offset_settings['time'] == 0):
            new_offset_settings['direction'] = '+'

        offset = offset_settings['logging']['time_offset']
        offset.update({
            'direction': new_offset_settings['direction'],
            'amount': int(new_offset_settings['time'])
        })

        dnx.write_configuration(offset_settings)

def set_syslog_settings(syslog_settings):
    with ConfigurationManager('syslog_client') as dnx:
        stored_syslog_settings = dnx.load_configuration()

        syslog = stored_syslog_settings['syslog']
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

        syslog['protocol'] = 6 if 'syslog_protocol' in syslog_settings['syslog'] else 17
        syslog['enabled'] = True if 'syslog_enabled' in syslog_settings['syslog'] else False

        tls_settings['retry'] = int(syslog_settings['tls_retry']) * 60
        tcp_settings['retry'] = int(syslog_settings['tcp_retry']) * 60

        dnx.write_configuration(stored_syslog_settings)

def set_syslog_servers(syslog_servers):
    with ConfigurationManager('syslog_client') as dnx:
        syslog_settings = dnx.load_configuration()

        servers = syslog_settings['syslog']['servers']
        for server, server_info in syslog_servers.items():
            if (not server_info['ip_address']): continue

            servers.update({
                server: {
                    'ip_address': server_info['ip_address'],
                    'port': int(server_info['port'])
                }})

        dnx.write_configuration(syslog_settings)

# NOTE: why is this returning a value? is this doing some validation checking?
def remove_syslog_server(syslog_server_number):
    with ConfigurationManager('syslog_client') as dnx:
        syslog_settings = dnx.load_configuration()

        servers = syslog_settings['syslog']['servers']
        result = servers.pop(f'Server{syslog_server_number}', False)
        if (result and 'server2' in servers):
            servers['server1'] = servers.pop('server2')

        dnx.write_configuration(syslog_settings)

    return result

def update_ip_restriction_settings(tr_settings):
    with ConfigurationManager('ip_proxy') as dnx:
        time_restriction_settings = dnx.load_configuration()

        hour = tr_settings['hour']
        if (tr_settings['suffix'] == 'PM'):
            hour += 12

        minutes = tr_settings['minutes']
        start_time = f'{hour}:{minutes}'

        tlen_hour = tr_settings['length_hour']
        min_fraction = str(tr_settings['length_minutes']/60).strip('0.')
        res_length = f'{tlen_hour}.{min_fraction}'
        res_length = int(float(res_length) * 3600)

        time_restriction = time_restriction_settings['ip_proxy']['time_restriction']
        time_restriction.update({
            'start': start_time,
            'length': res_length,
            'enabled': tr_settings['enabled']
            })

        dnx.write_configuration(time_restriction_settings)

# settings update service reset and error flags back to False/None.
def reset_module_flags(*, system=False, signatures=False, ruleset='both'):
    with ConfigurationManager('updates') as dnx:
        system_updates = dnx.load_configuration()
        if (system):
            system_status = system_updates['updates']['system']
            system_status.update({'restart': False, 'error': None})

        if (signatures and ruleset == 'domain'):
            signature_status = system_updates['updates']['signature']
            signature_status[ruleset].update({'restart': False, 'error': None})

        elif (signatures and ruleset == 'ip'):
            signature_status = system_updates['updates']['signature']
            signature_status[ruleset].update({'restart': False, 'error': None})

        elif (signatures and ruleset == 'both'):
            signature_status = system_updates['updates']['signature']
            for ruleset in ['domain', 'ip']:
                signature_status[ruleset].update({'restart': False, 'error': None})

        dnx.write_configuration(system_updates)

def set_dns_cache_clear_flag(clear_dns_cache):
    with ConfigurationManager('dns_server') as dnx:
        dns_server_settings = dnx.load_configuration()

        dns_cache_flags = dns_server_settings['dns_server']['cache']
        for flag, setting in clear_dns_cache.items():
            if (setting):
                dns_cache_flags[flag] = True

        dnx.write_configuration(dns_server_settings)

def reset_update_errors():
    with ConfigurationManager('updates') as dnx:
        update_settings = dnx.load_configuration()

        system_status = update_settings['updates']['system']
        signature_status = update_settings['updates']['signature']

        system_status['error'] = None
        for ruleset in ['domain', 'ip']:
            signature_status[ruleset]['error'] = None

        dnx.write_configuration(update_settings)

def set_ips_ddos(action):
    with ConfigurationManager('ips') as dnx:
        ips_settings = dnx.load_configuration()

        ips_settings['ips']['ddos']['enabled'] = action

        dnx.write_configuration(ips_settings)

def set_ips_portscan(portscan_settings):
    with ConfigurationManager('ips') as dnx:
        ips_settings = dnx.load_configuration()

        ps_settings = ips_settings['ips']['port_scan']

        ps_settings['enabled'] = True if 'enabled' in portscan_settings else False
        ps_settings['reject']  = True if 'reject' in portscan_settings else False

        dnx.write_configuration(ips_settings)

def set_ips_general_settings(pb_length, ids_mode):
    with ConfigurationManager('ips') as dnx:
        ips_settings = dnx.load_configuration()

        ips_settings['ips']['passive_block_ttl'] = pb_length
        ips_settings['ips']['ids_mode'] = ids_mode

        dnx.write_configuration(ips_settings)

def set_ips_ddos_limits(ddos_limits):
    with ConfigurationManager('ips') as dnx:
        ips_settings = dnx.load_configuration()

        limits = ips_settings['ips']['ddos']['limits']['source']
        for protocol, limit in ddos_limits.items():
            limits[protocol] = limit

        dnx.write_configuration(ips_settings)

# True > User Config | False > restore DHCP
def set_wan_interface(settings=None):
    ## Opening Config JASON file and updating WAN Interface information to be
    ## viewed by the front end
    with ConfigurationManager('config') as dnx:
        interface_settings = dnx.load_configuration()

        interface = interface_settings['settings']['interface']
        wan_config = interface['wan']

        #Checking configured DNS Servers
        dns_server_settings = load_configuration('dns_server')

        resolvers = dns_server_settings['dns_server']['resolvers']
        dns1 = resolvers['server1']['ip_address']
        dns2 = resolvers['server2']['ip_address']

        #Settings DHCP to false in json file for use by front end
        wan_config['dhcp'] = False if settings else True

        ## setting local copy of wan interface configuration to user defined options
        ## then moving the file to the systemd/network folder and finally restarting
        ## networkd service for changes to take affect
        with open(f'{HOME_DIR}/dnx_system/interface/wan_template', 'r') as wan_template_file:
            wan_template = wan_template_file.readlines()

        dns_counter = 1
        with open(f'{HOME_DIR}/dnx_system/interface/wan.network', 'w') as wan_settings:
            for line in wan_template:
                if ('Address' in line and settings):
                    wan_ip = settings['ip_address']
                    wan_cidr = settings['cidr']
                    wan_address = f'{wan_ip}/{wan_cidr}'
                    line = line.replace('NULL', wan_address)
                elif ('Gateway' in line and settings):
                    line = line.replace('NULL', settings['default_gateway'])
                elif ('DNS' in line):
                    #NOTE: i dont care
                    line = line.replace('NULL', eval(f'dns{dns_counter}'))
                    dns_counter += 1
                wan_settings.write(line)

        # NOTE: python should be able to do this safer, also make the front end notify user of error and log!!!
        try:
            int_change = run(f'sudo mv {HOME_DIR}/dnx_system/interface/wan.network /etc/systemd/network/wan.network', shell=True)
            int_change.check_returncode()
        except CalledProcessError as cpe:
            return cpe
        else:
            Services.restart('systemd-networkd')
            dnx.write_configuration(interface_settings)

def add_open_wan_protocol(protocol, dst_port, host_port):
    with ConfigurationManager('ips') as dnx:
        open_protocol_settings = dnx.load_configuration()

        open_protocols = open_protocol_settings['ips']['open_protocols']
        if (dst_port):
            open_protocols[protocol][dst_port] = host_port
        # this is handling icmp i think.
        else:
            open_protocols[protocol] = True

        dnx.write_configuration(open_protocol_settings)

def del_open_wan_protocol(rule_number):
    with ConfigurationManager('ips') as dnx:
        open_protocol_settings = dnx.load_configuration()

        open_protocols = open_protocol_settings['ips']['open_protocols']
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
