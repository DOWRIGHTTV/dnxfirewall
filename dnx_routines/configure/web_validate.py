#!/usr/bin/env python3

import re
import json

from subprocess import run
from collections import namedtuple
from ipaddress import IPv4Address, IPv4Network

from flask import Flask

from dnx_gentools.def_constants import LOG, CFG, DATA, PROTO, INVALID_FORM
from dnx_gentools.file_operations import load_configuration
from dnx_routines.configure.exceptions import ValidationError
from dnx_secmods.cfirewall.fw_manage import FirewallManage

MIN_PORT = 1
MAX_PORT = 65535
MAX_PORT_RANGE = 65536

__all__ = (
    'standard', 'syslog_dropdown', 'mac_address',
    'ip_address', 'default_gateway', 'domain',
    'cidr', 'network_port', 'timer',
    'account_creation', 'username', 'password',
    'user_role', 'dhcp_reservation', 'log_settings',
    'time_offset', 'syslog_settings', 'ip_proxy_settings',
    'time_restriction', 'dns_over_tls', 'portscan_settings',
    'ips_passive_block_length', 'add_ip_whitelist', 'domain_categories',
    'dns_record',
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

            raise ValidationError(f'Standard fields can only contain alpha numeric characters or the following {override}.')

def syslog_dropdown(syslog_time):
    syslog_time = convert_int(syslog_time)
    if (syslog_time):
        raise ValidationError('Dropdown values must be an integer.')

    if (syslog_time not in [5, 10, 60]):
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

# this is a convenience wrapper around above function to allow for multiple ips to be checked with one func call.
def ip_address(ip_addr=None, *, ip_iter=None):
    ip_iter = [] if not ip_iter else ip_iter
    if (not isinstance(ip_iter, list)):
        return ValidationError('Data format must be a list.')

    if (ip_addr):
        ip_iter.append(ip_addr)

    for ip in ip_iter:
        _ip_address(ip)

def ip_network(ip_netw, /):
    '''take ip network string, validates, then returns ip network string. the return string will always be the network
    id of the subnet.'''
    try:
        ip_netw = IPv4Network(ip_netw)
    except:
        raise ValidationError('IP network is not valid.')

    return int(ip_netw.network_address), ip_netw.prefixlen

def default_gateway(ip_addr, /):
    try:
        ip_addr = IPv4Address(ip_addr)
    except:
        raise ValidationError('Default gateway is not valid.')

    if (ip_addr.is_loopback):
        raise ValidationError('Default gateway cannot be 127.0.0.1/loopback.')

def domain(dom, /):
    if (not _VALID_DOMAIN.match(dom)):
        raise ValidationError('Domain is not valid.')

def cidr(cd, /):
    cd = convert_int(cd)
    if (cd not in range(0, 33)):
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
    # value in a port range is N/A for icmp, but in this case just letting it do what the others do.
    ports[1] = ports[1] if ports[1] != 0 else 65535

    for port in ports:

        # port 0 is used by icmp. if 0 is used outside icmp it gets converted to a range.
        if (port not in range(65536)):
            raise ValidationError(error)

    return proto_int, ports

def timer(val, /):
    val = convert_int(val)
    if (not 1 <= val <= 1440):
        raise ValidationError('Timer must be between 1 and 1440 (24 hours).')

def account_creation(account_info):
    '''Convenience function wrapping username, password, and user_role input validation functions. Username value
       will be updated to .lower() on successful validation.'''

    username(account_info['username'])
    password(account_info['password'])
    user_role(account_info['role'])

    # setting username to lowercase seems cleaner here
    account_info['username'] = account_info['username'].lower()

def username(user, /):
    if (not user.isalnum()):
        raise ValidationError('Username can only be alpha numeric characters.')

def password(passwd, /):
    # calculating the length
    if (len(passwd) < 8):
        raise ValidationError('Password does not meet length requirement of 8 characters.')

    criteria = (
        re.search(r'\d', passwd), re.search(r'[A-Z]', passwd), # searching for digits & uppercase
        re.search(r'[a-z]', passwd), re.search(r'\W', passwd) # searching for lowercase & symbols
    )

    if not all(criteria):
        raise ValidationError('Password does not meet complexity requirements.')

def user_role(role, /):
    if (role not in ['admin', 'user', 'cli']):
        raise ValidationError('Invalid user settings.')

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

def log_settings(settings, /):
    if (settings['length'] not in [30, 45, 60, 90]):
        raise ValidationError('Invalid log settings.')

    try:
        LOG(settings['level'])
    except ValueError:
        raise ValidationError('Invalid log settings.')

def time_offset(settings, /):
    direction = settings['direction']
    if (direction not in [' ', '-', '+']):
        raise ValidationError('Invalid time offset sign.')

    offset = settings['time']
    if (offset not in range(0,15)):
        raise ValidationError('Invalid time offset value.')

    if (direction == ' ' and offset != 0):
        raise ValidationError('Direction cannot be empty if amount is not zero.')

    elif (direction == '-' and offset in [13, 14]):
        raise ValidationError('Invalid timezone/ time offset.')

def syslog_settings(settings, /):
    syslog = load_configuration('syslog_client')

    return
    # configured_syslog_servers = syslog['servers']
    # if (not configured_syslog_servers):
    #     raise ValidationError('Syslog servers must be configured before modifying client settings.')
    #
    # tls_retry = convert_int(settings['tls_retry'])
    # tcp_retry = convert_int(settings['tcp_retry'])
    # tls_settings = settings['tls']
    # syslog_settings = settings['syslog']
    #
    # if (tls_retry not in [5, 10, 60] and tcp_retry not in [5, 10, 30]):
    #     raise ValidationError('Syslog settings are not valid.')
    #
    # for item in tls_settings:
    #     if (item not in ['enabled', 'tcp_fallback', 'udp_fallback', 'self_signed']):
    #         raise ValidationError('Syslog settings are not valid.')
    #
    # for item in syslog_settings:
    #     if (item not in ['syslog_enabled', 'syslog_protocol']):
    #         raise ValidationError('Syslog settings are not valid.')
    #
    # if ('syslog_protocol' not in syslog_settings):
    #     if ('encrypted_syslog' in tls_settings):
    #         raise ValidationError('TCP must be enabled to enable TLS.')
    #
    #     if ('tcp_fallback' in tls_settings):
    #         raise ValidationError('TLS must be enabled before TCP fallback.')

def ip_proxy_settings(host_categories, *, ruleset='reputation'):
    ip_proxy = load_configuration('ip_proxy')

    valid_categories = ip_proxy[ruleset]
    for category in host_categories:
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

    if (rtype not in ['country', 'continent']):
        raise ValidationError(INVALID_FORM)

    if (rtype == 'country'):
        valid_regions = load_configuration('ip_proxy')['geolocation']

    elif (rtype == 'continent'):
        valid_regions = load_configuration('geolocation', filepath='dnx_webui/data')

    else:
        raise ValidationError(INVALID_FORM)

    if (region[rtype] not in valid_regions):
        raise ValidationError(INVALID_FORM)

def time_restriction(settings, /):
    tr_hour = convert_int(settings['hour'])
    tr_min  = convert_int(settings['minutes'])

    if (tr_hour not in range(1, 13) or tr_min not in [00, 15, 30, 45]):
        raise ValidationError('Restriction settings are not valid.')

    tr_hour_len = convert_int(settings['length_hour'])
    tr_min_len  = convert_int(settings['length_minutes'])

    if (tr_hour_len not in range(1,13) and tr_min_len not in [00, 15, 30, 45]):
        raise ValidationError('Restriction settings are not valid.')

    if (settings['suffix'] not in ['AM', 'PM']):
        raise ValidationError('Restriction settings are not valid.')

def dns_over_tls(dns_tls_settings):
    dns_server = load_configuration('dns_server')

    current_tls = dns_server['tls']['enabled']
    for item in dns_tls_settings['enabled']:
        if (item not in ['dns_over_tls', 'udp_fallback']):
            raise ValidationError(INVALID_FORM)

    # NOTE: current_tls shouldn't matter since tls will be in form if enabled regardless
    if (not current_tls and 'udp_fallback' in dns_tls_settings['enabled']
            and 'dns_over_tls' not in dns_tls_settings['enabled']):
        raise ValidationError('DNS over TLS must be enabled to configure UDP fallback.')

def firewall_commit(fw_rules, /):
    # ["1", "lan_dhcp_allow", "lan", "tv,lan_network tv,dmz_network", "track_changes,udp_any", "any",
    #  "tv,lan_network tv,dmz_network", "track_changes,udp_67", "ACCEPT", "OFF", "0", "0"]

    fw_rules = json.loads(fw_rules)

    # TODO: move this somewhere else. maybe top of file.
    rule_structure = namedtuple('rule_structure', [
        'enabled', 'name',
        'src_zone', 'src_network', 'src_service',
        'dst_zone', 'dst_network', 'dst_service',
        'action', 'log', 'sec1_prof', 'sec2_prof'
    ])

    validated_rules = {}

    # index/ enumerate is for providing better feedback if issues are detected.
    for i, rule in enumerate(fw_rules.values(), 1):

        try:
            rule = rule_structure(*rule)
        except ValueError:  # i think its a value error
            raise ValidationError(f'Format error found in rule #{i}')

        try:
            validated_rules[i] = manage_firewall_rule(i, rule)
        except ValidationError:
            raise

    print(validated_rules)
    return validated_rules

# NOTE: log disabled in form and set here as default for the time being.
def manage_firewall_rule(rule_num, fw_rule, /):

    # FASTER CHECKS FIRST
    if (fw_rule.action not in ['ACCEPT', 'DROP']):
        raise ValidationError(f'{INVALID_FORM} [rule #{rule_num}/action]')

    action = 1 if fw_rule.action == 'ACCEPT' else 0

    ip_proxy_profile = convert_int(fw_rule.sec1_prof)
    ips_ids_profile  = convert_int(fw_rule.sec2_prof)
    if not all([x in [0, 1] for x in [ip_proxy_profile, ips_ids_profile]]):
        raise ValidationError(f'Invalid security profile for rule #{rule_num}.')

    enabled = convert_int(fw_rule.enabled)

    # OBJECT VALIDATIONS
    check = Flask.app.dnx_object_manager.iter_validate

    src_network = check(fw_rule.src_network)
    if (None in src_network):
        raise ValidationError(f'A source network object was not found for rule #{rule_num}.')

    src_service = check(fw_rule.src_service)
    if (None in src_service):
        raise ValidationError(f'A source service object was not found for rule #{rule_num}.')

    dst_network = check(fw_rule.dst_network)
    if (None in dst_network):
        raise ValidationError(f'A destination network object was not found for rule #{rule_num}.')

    dst_service = check(fw_rule.src_service)
    if (None in dst_service):
        raise ValidationError(f'A destination service object was not found for rule #{rule_num}.')

    # TODO: make zone map integrated better
    dnx_interfaces = load_configuration('config')['interfaces']['builtins']
    zone_map = {zone_name: zone_info['zone'] for zone_name, zone_info in dnx_interfaces.items()}

    # 99 used to specify wildcard/any zone match
    zone_map['any'] = 99

    s_zone = zone_map.get(fw_rule.src_zone, None)
    d_zone = zone_map.get(fw_rule.dst_zone, None)
    if (s_zone is None or d_zone is None):
        raise ValidationError(f'{INVALID_FORM} [rule #{rule_num}/zone]')

    rule = {
        'name': fw_rule.name,
        'id': None,
        'enabled': enabled,
        'src_zone': [s_zone],                # [12]
        'src_network': src_network,
        'src_service': src_service,
        'dst_zone': [d_zone],                # [11]
        'dst_network': dst_network,
        'dst_service': dst_service,
        'action': action,                    # 1
        'log': 0,
        'ipp_profile': ip_proxy_profile,
        'ips_profile': ips_ids_profile
    }

    return rule

def add_dnat_rule(rule, /):
    # ensuring all necessary fields are present in the namespace before continuing.
    valid_fields = [
        'src_zone', 'dst_ip', 'dst_port', 'host_ip', 'host_port', 'protocol'
    ]

    if not all([hasattr(rule, x) for x in valid_fields]):
        raise ValidationError(INVALID_FORM)

    if (rule.protocol not in ['tcp', 'udp', 'icmp']):
        raise ValidationError(INVALID_FORM)

    if (not rule.dst_ip and rule.dst_port in ['443', '80']):
        raise ValidationError('Ports 80,443 cannot be set as destination port when destination IP is not set.')

    if (rule.protocol == 'icmp'):

        open_protocols = load_configuration('ips')
        if (open_protocols['open_protocols']['icmp']):
            return 'Only one ICMP rule can be active at a time. Remove existing rule before adding another.'

def del_nat_rule(rule, /):
    output = run(
        f'sudo iptables -t nat -nL {rule.nat_type} --line-number', shell=True, capture_output=True
    ).stdout.splitlines()[1:]

    rule_count = len(output)
    if (convert_int(rule.position) not in range(1, rule_count+1)):
        raise ValidationError('Selected rule is not valid and cannot be removed.')

    # validating fields for removing the associated open protocol/port from the tracker
    open_protocol_settings = load_configuration('ips')['open_protocols']
    try:
        rule.protocol, rule.port = rule.proto_port.split('/')
    except:
        raise ValidationError(INVALID_FORM)

    # tcp/udp checked first. if error, will check icmp format. if that doesnt match then
    # exception is raised.
    try:
        open_protocol_settings[rule.protocol][rule.port]
    except:
        if (rule.protocol != 'icmp' and rule.port != '0'):
            raise ValidationError(INVALID_FORM)

def add_snat_rule(rule, /):
    # ensuring all necessary fields are present in the namespace before continuing.
    valid_fields = [
        'src_zone', 'orig_src_ip', 'new_src_ip',
    ]
    if not all([hasattr(rule, x) for x in valid_fields]):
        raise ValidationError('Invalid form.')

def portscan_settings(settings, /):
    ips = load_configuration('ips')

    current_prevention = ips['port_scan']['enabled']
    for item in settings:
        if (item not in ['enabled', 'reject']):
            raise ValidationError(INVALID_FORM)

    if ('reject' in portscan_settings and 'drop' not in settings and not current_prevention):
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

def ips_passive_block_length(length, /):
    if (length not in [0, 24, 48, 72]):
        raise ValidationError(INVALID_FORM)

def add_ip_whitelist(settings, /):
    # handling alphanum check. will raise exception if invalid.
    standard(settings['user'])

    if (settings['type'] not in ['global', 'tor']):
        raise ValidationError(INVALID_FORM)

    # if ip is valid this will return, otherwise a ValidationError will be raised.
    _ip_address(settings['user'])

def domain_categories(categories, ruleset):
    if (ruleset == 'default' and not all(['malicious' in categories, 'cryptominer' in categories])):
        raise ValidationError('Malicious and cryptominer categories cannot be disabled.')

    dns_proxy = load_configuration('dns_proxy')
    if (ruleset in ['default', 'user_defined']):
        cat_list = dns_proxy['categories'][ruleset]

    elif (ruleset in ['tlds']):
        cat_list = dns_proxy['tlds']

    else:
        raise ValidationError(INVALID_FORM)

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

def dns_record(query_name, *, action):

    if (action is CFG.ADD):

        if (not _VALID_DOMAIN.match(query_name) and not query_name.isalnum()):
            raise ValidationError('Local DNS record is not valid.')

    elif (action is CFG.DEL):
        dns_server = load_configuration('dns_server')

        if (query_name == 'dnx.firewall'):
            raise ValidationError('Cannot remove dnxfirewall dns record.')

        if (query_name not in dns_server['records']):
            raise ValidationError(INVALID_FORM)
