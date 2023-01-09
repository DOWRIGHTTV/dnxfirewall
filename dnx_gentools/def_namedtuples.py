#!/usr/bin/env python3

from __future__ import annotations

from collections import namedtuple as _namedtuple
from functools import lru_cache as _lru_cache

from dnx_gentools.def_enums import PROTO as _PROTO, DHCP as _DHCP, DNS_CAT as _DNS_CAT, IPS as _IPS
from dnx_gentools.def_enums import GEO as _GEO, DIR as _DIR
from dnx_gentools.def_enums import DECISION as _DECISION, GEOLOCATION as _GEOLOCATION, REPUTATION as _REPUTATION
from dnx_gentools.standard_tools import bytecontainer as _bytecontainer

from dnx_iptools.def_structs import dhcp_byte_pack as _dhcp_bp, dhcp_short_pack as _dhcp_sp, dhcp_long_pack as _dhcp_lp

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING
if (TYPE_CHECKING):
    from typing import NamedTuple as _NamedTuple, Union as _Union, Optional as _Optional, Any as _Any
    from typing import Callable as _Callable, ByteString as _ByteString

    from dnx_gentools.def_typing import Any as _Any, Socket_T, Lock_T, Address as _Address

# ================
# BYTE CONTAINERS
# ================
RESOURCE_RECORD = _bytecontainer('resource_record', 'name qtype qclass ttl data')

# ================
# NAMED TUPLES
# ================
class Item(_NamedTuple):
    key:   _Any
    value: _Any

class FW_OBJECT(_NamedTuple):
    id:      int
    name:    str
    origin:  str
    type:    str
    subtype: int
    value:   str
    description: str = ''

    @_lru_cache(maxsize=None)
    def __str__(self) -> str:
        '''convert the tuple to a list and return as a string.

        the @lru_cache decorator guarantees attribute indexing is done only once per object.
        '''
        return f"[{self[0]},'{self[1]}','{self[2]}','{self[3]}',{self[4]},'{self[5]}','{self[6]}']"


# DHCP SERVER
_pack_map: dict[int, _Callable[[int, int, int], bytes]] = {1: _dhcp_bp, 2: _dhcp_sp, 4: _dhcp_lp}
class DHCP_OPTION(_NamedTuple):
    code:  int
    size:  int
    value: int

    @_lru_cache(maxsize=None)
    def packed(self) -> bytes:
        '''pack a dhcp option into a byte string.

        the @lru_cache decorator guarantees the attribute lookup/ pack call are done only once per object.
        '''
        return _pack_map[self.size](self.code, self.size, self.value)

class DHCP_INTERFACE(_NamedTuple):
    en_check: list[int, int]
    ip:       int
    netid:    int
    netmask:  int
    h_range:  list[int, int]
    socket:   tuple[Socket_T, int]
    options:  dict[int, DHCP_OPTION]

class DHCP_RECORD(_NamedTuple):
    rtype:     _DHCP
    timestamp: int
    mac:       str
    hostname:  str

# short-lived container for queue/writing dhcp record to disk
class RECORD_CONTAINER(_NamedTuple):
    ip:     int
    record: DHCP_RECORD


# SYSLOG CLIENT
SYSLOG_SERVERS = _namedtuple('syslog_servers', 'primary secondary')

# DNS PROXY
DNS_WHITELIST = _namedtuple('whitelist', 'dns ip')
DNS_BLACKLIST = _namedtuple('blacklist', 'dns')
class DNS_SERVERS(_NamedTuple):
    primary:   dict[_Union[str, _PROTO], _Optional[bool]]
    secondary: dict[_Union[str, _PROTO], _Optional[bool]]

class RELAY_CONN(_NamedTuple):
    remote_ip: str
    sock: Socket_T
    send: _Callable[[_Union[bytes, bytearray]], int]
    recv: _Union[_Callable[[int], bytes], _Callable[[_Union[bytearray, memoryview]], int]]
    version: str

class QNAME_RECORD(_NamedTuple):
    expire:  int
    ttl:     int
    records: list[RESOURCE_RECORD]

class QNAME_RECORD_UPDATE(_NamedTuple):
    ttl:     int
    records: list[RESOURCE_RECORD]

class DNS_SIGNATURES(_NamedTuple):
    en_dns:  set[_DNS_CAT]
    tld:     dict[str, int]
    keyword: list[tuple[str, _DNS_CAT]]

class DNS_REQUEST_RESULTS(_NamedTuple):
    redirect: bool
    reason:   _Optional[str]
    category: _Optional[_DNS_CAT]

class DNS_SEND(_NamedTuple):
    qname: str
    data:  bytearray


# IPS/IDS
IPS_WAN_INFO = _namedtuple('ips_wan_info', 'interface ip mac')

class IPS_SCAN_RESULTS(_NamedTuple):
    initial_block: bool
    scan_detected: bool
    block_status:  _IPS

class PSCAN_TRACKERS(_NamedTuple):
    lock:    Lock_T
    tracker: dict[int, dict[str, _Any]]

class DDOS_TRACKERS(_NamedTuple):
    lock:    Lock_T
    tracker: dict[int, dict[str, _Any]]

# IP PROXY
class IPP_INSPECTION_RESULTS(_NamedTuple):
    category: tuple[_GEOLOCATION, _REPUTATION]
    action:   _DECISION

# LOG TUPLES
class IPP_EVENT_LOG(_NamedTuple):
    local_ip:   int
    tracked_ip: int
    category:   tuple[_GEOLOCATION, _REPUTATION]
    direction:  str
    action:     str

class DNS_REQUEST_LOG(_NamedTuple):
    src_ip:   str
    request:  str
    category: str
    reason:   str
    action:   str

class IPS_EVENT_LOG(_NamedTuple):
    attacker:    int
    protocol:    str
    attack_type: str
    action:      str

class GEOLOCATION_LOG(_NamedTuple):
    '''GENERAL GEOLOCATION LOG TUPLE.

    provides properties to convert integer values to std string form.
            (cty_name, dir_name, act_name)
    '''
    country:   int
    direction: int
    action:    int

    @property
    def cty_name(self) -> str:
        return _GEO(self.country).name.lower()

    @property
    def dir_name(self) -> str:
        return _DIR(self.direction).name.lower()

    @property
    def act_name(self) -> str:
        return 'allowed' if self.action == 1 else 'blocked'


class INF_EVENT_LOG(_NamedTuple):
    client_mac: str
    src_ip:     int
    detected_host: str
    reason:     str


# alias
DNS_BLOCKED_LOG = DNS_REQUEST_LOG

# DATABASE
BLOCKED_DOM = _namedtuple('blocked', 'domain category reason')

# SOCKET
class L_SOCK(_NamedTuple):
    name:     str
    ip:       int
    socket:   Socket_T
    send:     _Callable[[_Union[bytes, bytearray]], int]
    sendto:   _Callable[[_Union[bytes, bytearray], _Address], int]
    recvfrom: _Callable[[_Union[_ByteString, memoryview]], tuple[int, _Address]]

class NFQ_SEND_SOCK(_NamedTuple):
    zone: int
    ip:   int
    sock_sendto: _Callable[[_Union[bytes, bytearray], _Address], int]
