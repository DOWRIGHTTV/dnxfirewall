#!/usr/bin/env python3

from __future__ import annotations

import re
from ipaddress import IPv4Network

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import CFG, DATA, PROTO
from dnx_gentools.file_operations import load_configuration
from dnx_routines.configure.exceptions import ValidationError

MIN_PORT = 1
MAX_PORT = 65535
MAX_PORT_RANGE = MAX_PORT + 1

__all__ = (
    'INVALID_FORM',
    'standard',
    'convert_int', 'get_convert_int',
    'convert_bint', 'get_convert_bint',

    'mac_address',
    'ip_address', 'default_gateway', 'cidr',
    'network_port',

    'VALID_MAC', 'VALID_DOMAIN',

    'domain_name',
    'syslog_settings',
    'syslog_dropdown',
    'add_ip_whitelist',
    'ValidationError'
)

_proto_map = {'any': 0, 'icmp': 1, 'tcp': 6, 'udp': 17}

# TODO: mac regex allows trailing characters. it should hard cut after the exact char length.
VALID_MAC = re.compile('(?:[0-9a-fA-F]:?){12}')
VALID_DOMAIN = re.compile('(//|\\s+|^)(\\w\\.|\\w[A-Za-z0-9-]{0,61}\\w\\.){1,3}[A-Za-z]{2,6}')

def get_convert_int(form, key):
    '''gets string value from submitted form then converts into an integer and returns.

    If key is not present or string cannot be converted, an IntEnum representing the error will be returned.'''

    try:
        value = form.get(key, DATA.MISSING)

        return value if value == DATA.MISSING else int(value)
    except:
        return DATA.INVALID

def get_convert_bint(form, key: str) -> Union[int, DATA]:
    '''gets string value from submitted form and converts into an integer representation of bool.

    If the key is not present 0 (False) will be returned.
    If string cannot be converted, error will be returned.'''

    try:
        value = form.get(key, DATA.MISSING)

        return 0 if value == DATA.MISSING else int(value) & 1
    except:
        return DATA.INVALID

def convert_bint(num: Union[str, bool]) -> Union[int, DATA]:
    '''converts argument into an integer representation of bool, then returns. DATA.INVALID (-1) will
    be returned on error.'''
    try:
        return int(num) & 1
    except:
        return DATA.INVALID

def convert_float(num: str) -> Union[float, DATA]:
    '''converts argument into a float, then returns. DATA.INVALID (-1) will be returned on error.'''
    try:
        return float(num)
    except:
        return DATA.INVALID

def convert_int(num: Union[str, bool]) -> Union[int, DATA]:
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
    if (not VALID_MAC.match(mac)):
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

def ip_network(net: str, /) -> tuple[int, int]:
    try:
        ip_netw = IPv4Network(net)
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

def domain_name(dom: str, /):
    if (not VALID_DOMAIN.match(dom)):
        raise ValidationError('Domain is not valid.')

def cidr(cd: str, /) -> None:
    if (convert_int(cd) not in range(0, 33)):
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

def add_ip_whitelist(settings, /):
    # handling alphanum check. will raise exception if invalid.
    standard(settings['user'])

    if (settings['type'] not in ['global', 'tor']):
        raise ValidationError(INVALID_FORM)

    # if ip is valid this will return, otherwise a ValidationError will be raised.
    _ip_address(settings['user'])
