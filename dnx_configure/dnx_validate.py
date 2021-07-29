#!/usr/bin/env python3

import os, sys
import json
import string
import re

from subprocess import run
from ipaddress import IPv4Address, IPv4Network

_HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, _HOME_DIR)

from dnx_configure.dnx_constants import LOG, DATA, INVALID_FORM
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError

# TODO: why no CSRF. :(

__all__ = (
    'standard', 'syslog_dropdown', 'mac_address',
    'ip_address', 'default_gateway', 'domain',
    'cidr', 'network_port', 'timer', 'license',
    'account_creation', 'username', 'password',
    'user_role', 'dhcp_reservation', 'log_settings',
    'time_offset', 'syslog_settings', 'ip_proxy_settings',
    'time_restriction', 'dns_over_tls', 'del_firewall_rule',
    'add_firewall_rule', 'portscan_settings',
    'ips_passive_block_length', 'add_ip_whitelist',
    'main_services', 'domain_categories',
    'dns_record_add', 'dns_record_remove', # NOTE: these names should be flipped
    'ValidationError'
)

# TODO: mac regex allows trailing characters. it should hard cut after the exact char length.
_VALID_MAC = re.compile('(?:[0-9a-fA-F]:?){12}')
_VALID_DOMAIN = re.compile('(//|\\s+|^)(\\w\\.|\\w[A-Za-z0-9-]{0,61}\\w\\.){1,3}[A-Za-z]{2,6}')

def get_convert_int(form, key):
    '''gets string value from submitted form then converts into an integer and returns. If key is not present
    or string cannot be converted an IntEnum representing the error will be returned.'''

    try:
        value = form.get(key, DATA.MISSING)

        return value if value == DATA.MISSING else int(value)
    except:
        return DATA.INVALID

def convert_int(num):
    '''converts argument into an integer, then returns. -1 will be returned on error.'''
    try:
        return int(num)
    except:
        return DATA.INVALID

def standard(user_input, *, override=[]):
    for char in user_input:
        if (not char.isalnum() and char not in override):
            override = ', '.join(override)

            # TODO: FUCK ENGLISH. MAKE THIS MAKE SENSE PLEASE GOD. FUCK.
            raise ValidationError(f'Standard fields can only contain alpha numeric {override}.')

def syslog_dropdown(syslog_time):
    syslog_time = convert_int(syslog_time)
    if (syslog_time):
        raise ValidationError('Dropdown values must be an integer.')

    if (syslog_time not in [5,10,60]):
        raise ValidationError('Dropdown values can only be 5, 10, or 60.')

def mac_address(mac):
    if (not _VALID_MAC.match(mac)):
        raise ValidationError('MAC Address is not valid.')

def _ip_address(ip_addr):
    try:
        ip_addr = IPv4Address(ip_addr)
    except:
        raise ValidationError('IP Address is not valid.')

    if (ip_addr.is_loopback):
        raise ValidationError('IP Address cannot be 127.0.0.1/loopback.')

# this is convienience wrapper around above function to allow for multiple ips to be checked with one func call.
def ip_address(ip_addr=None, *, ip_iter=None):
    ip_iter = [] if not ip_iter else ip_iter
    if (not isinstance(ip_iter, list)):
        return ValidationError('Data format must be a list.')

    if (ip_addr):
        ip_iter.append(ip_addr)

    for ip in ip_iter:
        _ip_address(ip)

def default_gateway(ip_addr):
    try:
        ip_addr = IPv4Address(ip_addr)
    except:
        raise ValidationError('Default gateway is not valid.')

    if (ip_addr.is_loopback):
        raise ValidationError('Default gateway cannot be 127.0.0.1/loopback.')

def domain(domain):
    if (not _VALID_DOMAIN.match(domain)):
        raise ValidationError('Domain is not valid.')

def cidr(cidr):
    cidr = convert_int(cidr)
    if (cidr not in range(0,33)):
        raise ValidationError('Netmask must be in range 0-32.')

def network_port(port):
    port = convert_int(port)
    if (port not in range(0,65536)):
        raise ValidationError('TCP/UDP port must be in range 1-65535.')

def timer(timer):
    timer = convert_int(timer)
    if (not 1 < timer < 1440):
        raise ValidationError('Timer must be between 1 and 1440 (24 hours).')

def license(user_input):
    user_input = user_input.lower()
    digits = set(string.digits)
    let_lower = set(string.ascii_lowercase)
    for letter in user_input:
        if (letter == '-'): continue

        if (letter not in digits and letter not in let_lower):
            raise ValidationError('Standard fields can only contain alpha numeric characters.')

def account_creation(account_info):
    username(account_info['username'])
    password(account_info['password'])
    user_role(account_info['role'])

def username(username):
    if (not username.isalnum()):
        raise ValidationError('Username can only be alpha numeric characters.')

def password(password):
    # calculating the length
    if (len(password) < 8):
        raise ValidationError('Password does not meet length requirement of 8 characters.')

    # searching for digits
    if (not re.search(r'\d', password)
            # searching for uppercase
            or not re.search(r'[A-Z]', password)
            # searching for lowercase
            or not re.search(r'[a-z]', password)
            # searching for symbols
            or not re.search(r'\W', password)):

        raise ValidationError('Password does not meet complexity requirements.')

def user_role(user_role):
    if (user_role not in ['admin', 'user', 'cli']):
        raise ValidationError('User settings are not valid.')

def dhcp_reservation(reservation_settings):
    standard(reservation_settings['description'], override=[' '])
    mac_address(reservation_settings['mac'])
    _ip_address(reservation_settings['ip'])

    dhcp_settings = load_configuration('config')['settings']

    zone_net = IPv4Network(dhcp_settings['interfaces'][reservation_settings['zone'].lower()]['subnet'])
    if (IPv4Address(reservation_settings['ip']) not in zone_net.hosts()):
        raise ValidationError(f'IP Address must fall within {str(zone_net)} range.')

    # converting mac address into storing format. taking burden from front end and configuration methods.
    reservation_settings['mac'] = reservation_settings['mac'].lower().replace(':', '')

def dhcp_general_settings(server_settings):
    if (server_settings['interface'] not in ['lan', 'dmz']):
        raise ValidationError('Invalid interface referenced.')

    lease_range = server_settings['lease_range']

    # clamping range into lan/dmz class C's. this will have to change later if more control over interface
    # configurations is implemented.
    for field in lease_range.values():
        # print(type(field))
        if (field not in range(2,255)):
            raise ValidationError('DHCP ranges must be between 2 and 254.')

    if (lease_range['start'] >= lease_range['end']):
        raise ValidationError('DHCP pool start value must be less than the end value.')

def log_settings(log_settings):
    if (log_settings['length'] not in [30, 45, 60, 90]):
        raise ValidationError('Log settings are not valid.')

    try:
        LOG(log_settings['level'])
    except ValueError:
        raise ValidationError('Log settings are not valid.')

def time_offset(offset_settings):
    dir_offset = offset_settings['direction']
    if (dir_offset not in [' ', '-', '+']):
        raise ValidationError('Time offset direction is not valid.')

    time_offset = offset_settings['time']
    if (time_offset not in range(0,15)):
        raise ValidationError('Time offset amount is not valid.')

    if (dir_offset == ' ' and time_offset != 0):
        raise ValidationError('Direction cannot be empty if amount is not zero.')

    elif (dir_offset == '-' and time_offset in [13, 14]):
        raise ValidationError('Selected timezone is not valid.')

def syslog_settings(syslog_settings):
    syslog = load_configuration('syslog_client')['syslog']

    configured_syslog_servers = syslog['servers']
    if (not configured_syslog_servers):
        raise ValidationError('Syslog servers must be configured before modifying client settings.')

    tls_retry = convert_int(syslog_settings['tls_retry'])
    tcp_retry = convert_int(syslog_settings['tcp_retry'])
    tls_settings = syslog_settings['tls']
    syslog_settings = syslog_settings['syslog']

    if (tls_retry not in [5, 10, 60] and tcp_retry not in [5, 10, 30]):
        raise ValidationError('Syslog settings are not valid.')

    for item in tls_settings:
        if (item not in ['enabled', 'tcp_fallback', 'udp_fallback', 'self_signed']):
            raise ValidationError('Syslog settings are not valid.')

    for item in syslog_settings:
        if (item not in ['syslog_enabled', 'syslog_protocol']):
            raise ValidationError('Syslog settings are not valid.')

    if ('syslog_protocol' not in syslog_settings):
        if ('encrypted_syslog' in tls_settings):
            raise ValidationError('TCP must be enabled to enable TLS.')

        if ('tcp_fallback' in tls_settings):
            raise ValidationError('TLS must be enabled before TCP fallback.')

def ip_proxy_settings(ip_hosts_settings, *, ruleset='categories'):
    ip_proxy = load_configuration('ip_proxy')['ip_proxy']

    valid_categories = ip_proxy[ruleset]
    for category in ip_hosts_settings:
        try:
            category, direction = category[:-2], category[-1]
        except:
            raise ValidationError(INVALID_FORM)

        if (category not in valid_categories):
            raise ValidationError(INVALID_FORM)

        direction = convert_int(direction)
        if (direction not in range(4)):
            raise ValidationError(INVALID_FORM)

def time_restriction(tr_settings):
    tr_hour = convert_int(tr_settings['hour'])
    tr_min  = convert_int(tr_settings['minutes'])

    if (tr_hour not in range(1,13) or tr_min not in [00, 15, 30, 45]):
        raise ValidationError('Restriction settings are not valid.')

    tr_hour_len = convert_int(tr_settings['length_hour'])
    tr_min_len  = convert_int(tr_settings['length_minutes'])

    if (tr_hour_len not in range(1,13) and tr_min_len not in [00, 15, 30, 45]):
        raise ValidationError('Restriction settings are not valid.')

    if (tr_settings['suffix'] not in ['AM', 'PM']):
        raise ValidationError('Restriction settings are not valid.')

def dns_over_tls(dns_tls_settings):
    dns_server = load_configuration('dns_server')['dns_server']

    current_tls = dns_server['tls']['enabled']
    for item in dns_tls_settings['enabled']:
        if (item not in ['dns_over_tls', 'udp_fallback']):
            raise ValidationError(INVALID_FORM)

    # NOTE: current_tls shouldnt matter since tls will be in form if enabled regardless
    if (not current_tls and 'udp_fallback' in dns_tls_settings['enabled']
            and 'dns_over_tls' not in dns_tls_settings['enabled']):
        raise ValidationError('DNS over TLS must be enabled to configure UDP fallback.')

def del_firewall_rule(fw_rule):
    output = run(
        f'sudo iptables -nL {fw_rule.zone} --line-number', shell=True, capture_output=True
    ).stdout.splitlines()

    rule_count = len(output) + 2
    if (convert_int(fw_rule.position) not in range(1, rule_count)):
        raise ValidationError('Selected rule is not valid and cannot be removed.')

def add_firewall_rule(fw_rule):
    # ensuring all necessary fields are present in the namespace before continuing.
    valid_fields = [
        'action', 'dst_ip', 'dst_netmask', 'dst_port', 'position',
        'protocol', 'src_ip', 'src_netmask', 'tab', 'zone'
    ]
    if not all([hasattr(fw_rule, x) for x in valid_fields]):
        raise ValidationError('Invalid form.')

    # grabbing list of configured iptable rules for the specified chain.
    output = run(
        f'sudo iptables -nL {fw_rule.zone} --line-number', shell=True, capture_output=True
    ).stdout.splitlines()[1:]

    rule_count = len(output)
    fw_rule.position = convert_int(fw_rule.position)
    if (not rule_count and fw_rule.position != 1):
        raise ValidationError('First firewall rule must have position 1.')

    if (not 0 < fw_rule.position <= rule_count+1):
        raise ValidationError(f'Position outside of valid range. (1-{rule_count+1})')

    if (fw_rule.protocol not in ['any', 'tcp', 'udp', 'icmp']):
        raise ValidationError('Network protocol is not valid.')

    if (fw_rule.protocol in ['any', 'icmp'] and fw_rule.dst_port):
        raise ValidationError('Only TCP/UDP use destination port field.')

def del_nat_rule(nat_rule):
    output = run(
        f'sudo iptables -t nat -nL {nat_rule.nat_type} --line-number', shell=True, capture_output=True
    ).stdout.splitlines()[1:]

    rule_count = len(output)
    if (convert_int(nat_rule.position) not in range(1, rule_count+1)):
        raise ValidationError('Selected rule is not valid and cannot be removed.')

def add_dnat_rule(nat_rule):
    # ensuring all necessary fields are present in the namespace before continuing.
    valid_fields = [
        'src_zone', 'dst_ip', 'dst_port', 'host_ip', 'host_port', 'protocol'
    ]
    if not all([hasattr(nat_rule, x) for x in valid_fields]):
        raise ValidationError('Invalid form.')

    if (not nat_rule.dst_ip and nat_rule.dst_port in ['443', '80']):
        raise ValidationError('Ports 80,443 cannot be set as destination port when destination IP is not set.')

    if (nat_rule.protocol == 'icmp'):
        open_protocols = load_configuration('ips')['ips']

        if (open_protocols['open_protocols']['icmp']):
            return 'Only one ICMP rule can be active at a time. Remove existing rule before adding another.'

def add_snat_rule(nat_rule):
    # ensuring all necessary fields are present in the namespace before continuing.
    valid_fields = [
        'src_zone', 'orig_src_ip', 'new_src_ip',
    ]
    if not all([hasattr(nat_rule, x) for x in valid_fields]):
        raise ValidationError('Invalid form.')

def portscan_settings(portscan_settings):
    ips = load_configuration('ips')['ips']

    current_prevention = ips['port_scan']['enabled']
    for item in portscan_settings:
        if (item not in ['enabled', 'reject']):
            raise ValidationError(INVALID_FORM)

    if ('reject' in portscan_settings and 'drop' not in portscan_settings
            and not current_prevention):
        raise ValidationError('Prevention must be enabled to configure portscan reject.')

def management_access(zone, service):
    if (zone not in ['lan', 'dmz'] or service not in ['webui', 'cli', 'ssh']):
        raise ValidationError('Invalid form.')

def ips_passive_block_length(pb_length):
    pb_length = convert_int(pb_length)
    if (pb_length not in [0, 24, 48, 72]):
        raise ValidationError(INVALID_FORM)

    return pb_length

def add_ip_whitelist(whitelist_settings):
    # handling alphanum check. will raise exception if invalid.
    standard(whitelist_settings['user'])

    if (whitelist_settings['type'] not in ['global', 'tor']):
        raise ValidationError(INVALID_FORM)

    # if ip is valid this will return, otherwise a ValidationError will be raised.
    _ip_address(whitelist_settings['user'])

def main_services(services_form):
    valid_services = ['dnx-dns-proxy', 'dnx-fw-proxy', 'dnx-dhcp-server', 'dnx-updates']
    service = services_form['service']
    ruleset = services_form['ruleset']

    if (service not in valid_services):
        raise ValidationError(INVALID_FORM)

    if (service in ['dnx-dns-proxy', 'dnx-ip-proxy'] and ruleset is None):
        raise ValidationError(INVALID_FORM)

def domain_categories(categories, ruleset):
    if (ruleset == 'default' and not all(['malicious' in categories, 'cryptominer' in categories])):
        raise ValidationError('Malicious and cryptominer categories cannot be disabled.')

    dns_proxy = load_configuration('dns_proxy')['dns_proxy']
    if (ruleset in ['default', 'user_defined']):
        cat_list = dns_proxy['categories'][ruleset]

    elif (ruleset in ['tlds']):
        cat_list = dns_proxy['tlds']

    for category in categories:
        if category not in cat_list:
            raise ValidationError(INVALID_FORM)

def domain_category_keywords(categories):
    dns_proxy = load_configuration('dns_proxy')['dns_proxy']

    domain_cats = dns_proxy['categories']['default']
    for cat in categories:
        if (cat not in domain_cats):
            raise ValidationError(INVALID_FORM)

        if (not domain_cats[cat]['enabled']):
            raise ValidationError(INVALID_FORM)

def dns_record_add(dns_record_name):
    if (not _VALID_DOMAIN.match(dns_record_name)
            and not dns_record_name.isalnum()):
        raise ValidationError('Local dns record is not valid.')

def dns_record_remove(dns_record_name):
    dns_server = load_configuration('dns_server')['dns_server']

    if (dns_record_name == 'dnx.firewall'):
        raise ValidationError('Cannot remove dnxfirewall dns record.')

    if (dns_record_name not in dns_server['records']):
        raise ValidationError(INVALID_FORM)
