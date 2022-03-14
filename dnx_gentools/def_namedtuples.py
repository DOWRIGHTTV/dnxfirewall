#!/usr/bin/env python3

from __future__ import annotations

from collections import namedtuple as _namedtuple
from functools import lru_cache as _lru_cache
from typing import NamedTuple as _NamedTuple, Union as _Union, Optional as _Optional, Any as _Any, Callable as _Callable

from dnx_gentools.def_enums import PROTO as _PROTO, DHCP as _DHCP, DNS_CAT as _DNS_CAT
from dnx_gentools.standard_tools import bytecontainer as _bytecontainer

from dnx_iptools.def_structs import dhcp_byte_pack as _dhcp_bp, dhcp_short_pack as _dhcp_sp, dhcp_long_pack as _dhcp_lp

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING
if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Socket

# ================
# BYTE CONTAINERS
# ================
RESOURCE_RECORD = _bytecontainer('resource_record', 'name qtype qclass ttl data')

# ================
# NAMED TUPLES
# ================
class Item(_NamedTuple):
    key: _Any
    value: _Any


# DHCP SERVER
DHCP_REQUEST_INFO = _namedtuple(
    'dhcp_request_info', 'message_type, xID, server_identifier, mac_address, client_address, requested_ip'
)
DHCP_RESPONSE_INFO = _namedtuple('dhcp_response_info', 'xID mac_address ciaddr handout_ip options')

_pack_map: dict[int, _Callable[[int, int, int], bytes]] = {1: _dhcp_bp, 2: _dhcp_sp, 4: _dhcp_lp}
class DHCP_OPTION(_NamedTuple):
    code: int
    size: int
    value: int

    @_lru_cache(maxsize=None)
    def packed(self) -> bytes:
        '''pack a dhcp option into a byte string.

        the @lru_cache decorator guarantees the attribute lookup/ pack call are done once.
        '''
        return _pack_map[self.size](self.code, self.size, self.value)

class DHCP_RECORD(_NamedTuple):
    rtype: _DHCP
    timestamp: int
    mac: str
    hostname: str

# short-lived container for queue/writing dhcp record to disk
class RECORD_CONTAINER(_NamedTuple):
    ip: int
    record: DHCP_RECORD


# SYSLOG CLIENT
SYSLOG_SERVERS = _namedtuple('syslog_servers', 'primary secondary')

# DNS PROXY
PROXY_DECISION = _namedtuple('proxy_decision', 'name decision')
DNS_LOG = _namedtuple('dns_log', 'src_ip request category reason action')
BLOCKED_LOG = _namedtuple('blocked_log', 'src_ip request category reason action')

DNS_WHITELIST = _namedtuple('whitelist', 'dns ip')
DNS_BLACKLIST = _namedtuple('blacklist', 'dns')
class DNS_SERVERS(_NamedTuple):
    primary: dict[_Union[str, _PROTO], _Optional[bool]]
    secondary: dict[_Union[str, _PROTO], _Optional[bool]]

class RELAY_CONN(_NamedTuple):
    remote_ip: str
    sock: Socket
    send: _Callable[[_Union[bytes, bytearray]], int]
    recv: _Union[_Callable[[int], bytes], _Callable[[_Union[bytearray, memoryview]], int]]
    version: str

class QNAME_RECORD(_NamedTuple):
    expire: int
    ttl: int
    records: list[RESOURCE_RECORD]

class QNAME_RECORD_UPDATE(_NamedTuple):
    ttl: int
    records: list[RESOURCE_RECORD]

class DNS_SIGNATURES(_NamedTuple):
    en_dns: set[_DNS_CAT]
    tld: dict[str, int]
    keyword: list[tuple[str, _DNS_CAT]]

class DNS_REQUEST_RESULTS(_NamedTuple):
    redirect: bool
    reason: _Optional[str]
    category: _Optional[_DNS_CAT]

class DNS_SEND(_NamedTuple):
    qname: str
    data: bytearray


# IPS/IDS
IPS_WAN_INFO = _namedtuple('ips_wan_info', 'interface ip mac')
IPS_SCAN_RESULTS = _namedtuple('ips_scan_results', 'initial_block scan_detected block_status')
IPS_LOG = _namedtuple('ips_log', 'ip protocol attack_type action')
PSCAN_TRACKERS = _namedtuple('portscan', 'lock tracker')
DDOS_TRACKERS  = _namedtuple('ddos', 'lock tracker')

# IP PROXY
IPP_INSPECTION_RESULTS = _namedtuple('ipp_inspection_results', 'category action')
IPP_LOG = _namedtuple('ipp_log', 'local_ip tracked_ip category direction action')
GEO_LOG = _namedtuple('geo_log', 'country direction action')

IPP_SRC_INFO = _namedtuple('src_info', 'protocol src_ip src_port')
IPP_DST_INFO = _namedtuple('dst_info', 'protocol dst_ip dst_port')

# INFECTED CLIENTS
INFECTED_LOG = _namedtuple('infected_log', 'infected_client src_ip detected_host reason')

# DATABASE
BLOCKED_DOM = _namedtuple('blocked', 'domain category reason')

# SOCKET
L_SOCK = _namedtuple('listener_socket', 'name ip socket send sendto recvfrom')
# NFQ_SOCK = _namedtuple('socket_info', 'zone name mac ip sock')
NFQ_SEND_SOCK = _namedtuple('socket_info', 'zone ip sock_sendto')
