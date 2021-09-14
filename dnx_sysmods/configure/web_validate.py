#!/usr/bin/env python3

import os, sys
import re

from subprocess import run
from ipaddress import IPv4Address, IPv4Network

_HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-3]))
sys.path.insert(0, _HOME_DIR)

from dnx_sysmods.configure.def_constants import LOG, CFG, DATA, PROTO, INVALID_FORM
from dnx_sysmods.configure.file_operations import load_configuration
from dnx_sysmods.configure.exceptions import ValidationError
from dnx_secmods.cfirewall.fw_control import FirewallManage

MIN_PORT = 1
MAX_PORT = 65535
MAX_PORT_RANGE = 65536

# TODO: why no CSRF. :(

__all__ = (
    'standard', 'syslog_dropdown', 'mac_address',
    'ip_address', 'default_gateway', 'domain',
    'cidr', 'network_port', 'timer',
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

_proto_map = {'any': 0, 'icmp': 1, 'tcp': 6, 'udp': 17}

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

def convert_float(num):
    '''converts argument into a float, then returns. DATA.INVALID (-1) will be returned on error.'''
    try:
        return float(num)
    except:
        return DATA.INVALID

def convert_int(num):
    '''converts argument into an integer, then returns. DATA.INVALID (-1) will be returned on error.'''
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
        raise ValidationError('MAC address is not valid.')

def _ip_address(ip_addr):
    try:
        ip_addr = IPv4Address(ip_addr)
    except:
        raise ValidationError('IP address is not valid.')

    if (ip_addr.is_loopback):
        raise ValidationError('127.0.0.0/24 is reserved ip space and cannot be used.')

# this is convienience wrapper around above function to allow for multiple ips to be checked with one func call.
def ip_address(ip_addr=None, *, ip_iter=None):
    ip_iter = [] if not ip_iter else ip_iter
    if (not isinstance(ip_iter, list)):
        return ValidationError('Data format must be a list.')

    if (ip_addr):
        ip_iter.append(ip_addr)

    for ip in ip_iter:
        _ip_address(ip)

def ip_network(ip_netw):
    '''take ip network string, validates, then returns ip network string. the return string will always be the network
    id of the subnet.'''
    try:
        ip_netw = IPv4Network(ip_netw)
    except:
        raise ValidationError('IP network is not valid.')

    return int(ip_netw.network_address), ip_netw.prefixlen

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

# NOTE: split + iter is to support port ranges. limiting split to 1 to prevent 1:2:3 from being marked as valid.
def network_port(port, port_range=False):
    '''validates network ports 1-65535 or a range of 1-65535:1-65535'''

    if (port_range):
        ports = [convert_int(p) for p in port.split(':', 1)]
        additional = ' or a range of 1-65535:1-65535 '

    else:
        ports = [convert_int(port)]
        additional = ''

    if (len(ports) == 2):
        if (ports[0] >= ports[1]):
            raise ValidationError('Invalid range, the start value must be less than the end. ex. 9001:9002')

    for port in ports:

        if (port not in range(1, 65536)):
            raise ValidationError(f'TCP/UDP port must be between 1-65535{additional}.')

def proto_port(port_str):

    try:
        proto, port = port_str.split('/')
    except:
        raise ValidationError('Invalid protocol/port definition. ex tcp/80 or udp/500-550')

    proto_int = _proto_map.get(proto, None)
    if (proto_int is None):
        raise ValidationError('Invalid protocol. Use [any, tcp, udp, icmp].')

    # ensuring icmp definitions conform to required format.
    if (proto_int == PROTO.ICMP and convert_int(port) != 0):
        raise ValidationError('ICMP does not support ports. Use icmp/0.')

    # splitting str after the "/" on "-" which is port range operator. this will make range or singular definition
    # handling the same.
    ports = [convert_int(p) for p in port.split('-', 1)]

    if (len(ports) == 2):
        if (ports[0] > ports[1]):
            raise ValidationError('Invalid port range. The start value must be less than the end. ex. 9001-9002')

        error = f'TCP/UDP port range must be between within range 1-65535 or 0 for any. ex tcp/500-550, udp/0'

    else:
        # this puts single port in range syntax
        ports.append(ports[0])

        error = f'TCP/UDP port must be between 1-65535. ex udp/9001'

    # converting 0 port values to cover full range (0 is an alias for any). ICMP will not be converted to ensure
    # compatibility between icmp service definition vs any service. Any protocol will not be converted for same reason.
    if (proto_int not in [PROTO.ICMP, PROTO.ANY]):
        ports[0] = ports[0] if ports[0] != 0 else 1

    # expanding the range out for any. this does not cause issues with icmp since it does not use ports so the second
    # value in a port range is is N/A for icmp, but in this case just letting it do what the others do.
    ports[1] = ports[1] if ports[1] != 0 else 65535

    for port in ports:

        # port 0 is used by icmp. if 0 is used outside of icmp it gets converted to a range.
        if (port not in range(65536)):
            raise ValidationError(error)

    return proto_int, ports

def timer(timer):
    timer = convert_int(timer)
    if (not 1 < timer < 1440):
        raise ValidationError('Timer must be between 1 and 1440 (24 hours).')

def account_creation(account_info):
    '''Convenience function wrapping username, password, and user_role input validation functions. Username value
       will be updated to .lower() on successful validation.'''

    username(account_info['username'])
    password(account_info['password'])
    user_role(account_info['role'])

    account_info['username'] = account_info['username'].lower()

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

    dhcp_settings = load_configuration('config')

    zone_net = IPv4Network(dhcp_settings['interfaces']['builtins'][reservation_settings['zone'].lower()]['subnet'])
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
    syslog = load_configuration('syslog_client')

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

def ip_proxy_settings(ip_hosts_settings, *, ruleset='reputation'):
    ip_proxy = load_configuration('ip_proxy')

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

def geolocation(region, rtype='country'):
    region['cfg_dir'] = convert_int(region['cfg_dir'])
    if (region['cfg_dir'] not in range(4)):
        raise ValidationError(INVALID_FORM)

    if (rtype == 'country'):
        valid_regions = load_configuration('ip_proxy')['geolocation']

    elif (rtype == 'continent'):
        valid_regions = load_configuration('geolocation', filepath='dnx_webui/data')

    if region[rtype] not in valid_regions:
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
    dns_server = load_configuration('dns_server')

    current_tls = dns_server['tls']['enabled']
    for item in dns_tls_settings['enabled']:
        if (item not in ['dns_over_tls', 'udp_fallback']):
            raise ValidationError(INVALID_FORM)

    # NOTE: current_tls shouldnt matter since tls will be in form if enabled regardless
    if (not current_tls and 'udp_fallback' in dns_tls_settings['enabled']
            and 'dns_over_tls' not in dns_tls_settings['enabled']):
        raise ValidationError('DNS over TLS must be enabled to configure UDP fallback.')

# NOTE: log and security profiles are disabled in form. they will be set here as default for the time being.
def manage_firewall_rule(fw_rule):
    # ('position', '1'),
    # ('src_zone', 'lan'), ('src_ip', '192.168.83.0/24'), ('src_port', 'tcp/0'),
    # ('dst_zone', 'any'), ('dst_ip', '0.0.0.0/0'), ('dst_port', 'tcp/80'),
    # ('action', 'ACCEPT')
    # ensuring all necessary fields are present in the namespace before continuing.
    valid_fields = [
        'static_pos', 'position', 'section',
        'src_zone', 'src_ip', 'src_port',
        'dst_zone', 'dst_ip', 'dst_port',
        'action',
    ]
    if not all([hasattr(fw_rule, x) for x in valid_fields]):
        raise ValidationError(INVALID_FORM)

    if (fw_rule.action not in ['accept', 'deny']):
        raise ValidationError(INVALID_FORM)

    action = 1 if fw_rule.action == 'accept' else 0

    rule_list = FirewallManage.cfirewall.view_ruleset(section=fw_rule.section)
    if (rule_list is None):
        raise ValidationError(INVALID_FORM)

    rule_count = len(rule_list) + 1 # 1 for add and 1 for range non inclusivity
    if (convert_int(fw_rule.static_pos) not in range(1, rule_count)):
        raise ValidationError(INVALID_FORM)

    # this will allow for rule to be place beyond the last rule in list.
    if hasattr(fw_rule, 'create_rule'):
        rule_count += 1

    if (convert_int(fw_rule.position) not in range(1, rule_count)):
        raise ValidationError(INVALID_FORM)

    # appending /32 if / not present in string. the network test will catch malformed networks beyond that.
    if ('/' not in fw_rule.src_ip):
        fw_rule.src_ip += '/32'

    s_net, s_p_len = ip_network(fw_rule.src_ip)
    s_proto, s_ports = proto_port(fw_rule.src_port)

    # appending /32 if / not present in string. the network test will catch malformed networks beyond that.
    if ('/' not in fw_rule.dst_ip):
        fw_rule.dst_ip += '/32'

    d_net, d_p_len = ip_network(fw_rule.dst_ip)
    d_proto, d_ports = proto_port(fw_rule.dst_port)

    dnx_interfaces = load_configuration('config')['interfaces']['builtins']
    zone_map = {zone_name: zone_info['zone'] for zone_name, zone_info in dnx_interfaces.items()}
    zone_map['any'] = 0

    s_zone = zone_map.get(fw_rule.src_zone, None)
    d_zone = zone_map.get(fw_rule.dst_zone, None)
    if (s_zone is None or d_zone is None):
        raise ValidationError(INVALID_FORM)

    # en | zone | netid | mask | proto << p1 | p2 ---->    | action | log | ipp | ips
    # [1, 12, 4294967295, 32, 393217, 65535, 10, 4294967295, 32, 458751, 65535, 1, 0, 1, 1],

    return [
        1,
        s_zone, s_net, s_p_len, s_proto << 16 | s_ports[0], s_ports[1],
        d_zone, d_net, d_p_len, d_proto << 16 | d_ports[0], d_ports[1],
        action, 0, 1, 1
    ]

# NOTE: this will be deprecated with cfirewall implementation.
def del_firewall_rule(fw_rule):
    output = run(
        f'sudo iptables -nL {fw_rule.zone} --line-number', shell=True, capture_output=True
    ).stdout.splitlines()

    rule_count = len(output) + 2
    if (convert_int(fw_rule.position) not in range(1, rule_count)):
        raise ValidationError('Selected rule is not valid and cannot be removed.')

# NOTE: this will be deprecated with cfirewall implementation.
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

def add_dnat_rule(nat_rule):
    # ensuring all necessary fields are present in the namespace before continuing.
    valid_fields = [
        'src_zone', 'dst_ip', 'dst_port', 'host_ip', 'host_port', 'protocol'
    ]

    if not all([hasattr(nat_rule, x) for x in valid_fields]):
        raise ValidationError(INVALID_FORM)

    if (nat_rule.protocol not in ['tcp', 'udp', 'icmp']):
        raise ValidationError(INVALID_FORM)

    if (not nat_rule.dst_ip and nat_rule.dst_port in ['443', '80']):
        raise ValidationError('Ports 80,443 cannot be set as destination port when destination IP is not set.')

    if (nat_rule.protocol == 'icmp'):

        open_protocols = load_configuration('ips')
        if (open_protocols['open_protocols']['icmp']):
            return 'Only one ICMP rule can be active at a time. Remove existing rule before adding another.'

def del_nat_rule(nat_rule):
    output = run(
        f'sudo iptables -t nat -nL {nat_rule.nat_type} --line-number', shell=True, capture_output=True
    ).stdout.splitlines()[1:]

    rule_count = len(output)
    if (convert_int(nat_rule.position) not in range(1, rule_count+1)):
        raise ValidationError('Selected rule is not valid and cannot be removed.')

    # validating fields for removing the associated open protocol/port from the tracker
    open_protocol_settings = load_configuration('ips')['open_protocols']
    try:
        nat_rule.protocol, nat_rule.port = nat_rule.proto_port.split('/')
    except:
        raise ValidationError(INVALID_FORM)

    # tcp/udp checked first. if error, will check icmp format. if that doesnt match then
    # exception is raised.
    try:
        open_protocol_settings[nat_rule.protocol][nat_rule.port]
    except:
        if (nat_rule.protocol != 'icmp' and nat_rule.port != '0'):
            raise ValidationError(INVALID_FORM)

def add_snat_rule(nat_rule):
    # ensuring all necessary fields are present in the namespace before continuing.
    valid_fields = [
        'src_zone', 'orig_src_ip', 'new_src_ip',
    ]
    if not all([hasattr(nat_rule, x) for x in valid_fields]):
        raise ValidationError('Invalid form.')

def portscan_settings(portscan_settings):
    ips = load_configuration('ips')

    current_prevention = ips['port_scan']['enabled']
    for item in portscan_settings:
        if (item not in ['enabled', 'reject']):
            raise ValidationError(INVALID_FORM)

    if ('reject' in portscan_settings and 'drop' not in portscan_settings
            and not current_prevention):
        raise ValidationError('Prevention must be enabled to configure portscan reject.')

def management_access(fields):
    SERVICE_TO_PORT = {'webui': (80, 443), 'cli': (0,), 'ssh': (22,), 'ping': 1}

    if (fields.zone not in ['lan', 'dmz'] or fields.service not in ['webui', 'cli', 'ssh', 'ping']):
        raise ValidationError(INVALID_FORM)

    # convert_int will return -1  if issues with form data and ValueError will cover
    # invalid CFG action key/vals
    try:
        action = CFG(convert_int(fields.action))
    except ValueError:
        raise ValidationError(INVALID_FORM)

    fields.action = action
    fields.service_ports = SERVICE_TO_PORT[fields.service]

def ips_passive_block_length(pb_length):
    if (pb_length not in [0, 24, 48, 72]):
        raise ValidationError(INVALID_FORM)

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

    dns_proxy = load_configuration('dns_proxy')
    if (ruleset in ['default', 'user_defined']):
        cat_list = dns_proxy['categories'][ruleset]

    elif (ruleset in ['tlds']):
        cat_list = dns_proxy['tlds']

    for category in categories:
        if category not in cat_list:
            raise ValidationError(INVALID_FORM)

def domain_category_keywords(categories):
    dns_proxy = load_configuration('dns_proxy')

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
    dns_server = load_configuration('dns_server')

    if (dns_record_name == 'dnx.firewall'):
        raise ValidationError('Cannot remove dnxfirewall dns record.')

    if (dns_record_name not in dns_server['records']):
        raise ValidationError(INVALID_FORM)
