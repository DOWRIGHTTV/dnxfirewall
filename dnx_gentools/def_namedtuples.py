#!/usr/bin/env python3

from __future__ import annotations

from collections import namedtuple as _namedtuple
from functools import lru_cache as _lru_cache

from dnx_gentools.def_enums import PROTO as _PROTO, DHCP as _DHCP, DNS_CAT as _DNS_CAT, IPS as _IPS
from dnx_gentools.def_enums import GEO as _GEO, DIR as _DIR
from dnx_gentools.def_enums import DECISION as _DECISION
from dnx_gentools.standard_tools import bytecontainer as _bytecontainer

from dnx_iptools.def_structs import dhcp_byte_pack as _dhcp_bp, dhcp_short_pack as _dhcp_sp, dhcp_long_pack as _dhcp_lp

# ===============
# RUNTIME TYPES
# ===============
from typing import TYPE_CHECKING, NamedTuple as _NamedTuple

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_typing import TypeAlias, Union, Optional, Any, Bytes, Callable
    from dnx_gentools.def_typing import Socket_T, Lock_T, SEC_PROFILE, DNS_CAT_LABEL
    from dnx_gentools.def_typing import NET_ADDRESS, IP_ADDRINT

    from dnx_gentools.def_enums import NETWORK_PROTOCOL, GEOLOCATION, REPUTATION
    # NET_PORT as _NET_PORT, IP_ADDRESS as _IP_ADDRESS

class SigFile(_NamedTuple):
    '''
    ftype:    str
    folder:   str
    name:     str
    checksum: str
    '''
    ftype:    str
    folder:   str
    name:     str
    checksum: str

# ================
# BYTE CONTAINERS
# ================
RESOURCE_RECORD = _bytecontainer('resource_record', 'name qtype qclass ttl data')

# ================
# NAMED TUPLES
# ================
class Item(_NamedTuple):
    '''
    key:   str
    value: Union[None, int, str, float, bool, list, dict]
    '''
    key:   str
    value: Union[None, int, str, float, bool, list, dict]

class FW_OBJECT(_NamedTuple):
    '''
    id:      int
    name:    str
    origin:  str
    type:    str
    subtype: int
    value:   str
    description: str = ''
    '''
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

        the @lru_cache decorator guarantees attribute lookups are done only once per object.
        '''
        return f"[{self[0]},'{self[1]}','{self[2]}','{self[3]}',{self[4]},'{self[5]}','{self[6]}']"


# DHCP SERVER
_pack_map: dict[int, Callable[[int, int, int], bytes]] = {1: _dhcp_bp, 2: _dhcp_sp, 4: _dhcp_lp}
class DHCP_OPTION(_NamedTuple):
    '''
    code:  int
    size:  int
    value: int
    '''
    code:  int
    size:  int
    value: int

    @_lru_cache(maxsize=None)
    def packed(self) -> bytes:
        '''pack a dhcp option into a byte string.

        the @lru_cache decorator guarantees the attribute lookup/ pack call is done only once per object.
        '''
        return _pack_map[self.size](self.code, self.size, self.value)

class DHCP_INTERFACE(_NamedTuple):
    '''
    en_check: list[int, int]
    ip:       IP_ADDRINT
    netid:    IP_ADDRINT
    netmask:  IP_ADDRINT
    h_range:  list[int, int]
    socket:   tuple[Socket_T, int]
    options:  dict[int, DHCP_OPTION]
    '''
    en_check: list[int, int]
    ip:       IP_ADDRINT
    netid:    IP_ADDRINT
    netmask:  IP_ADDRINT
    h_range:  list[int, int]
    socket:   tuple[Socket_T, int]
    options:  dict[int, DHCP_OPTION]

class DHCP_RECORD(_NamedTuple):
    '''
    rtype:     _DHCP
    timestamp: int
    mac:       str
    hostname:  str
    '''
    rtype:     _DHCP
    timestamp: int
    mac:       str
    hostname:  str

# short-lived container for queue/writing dhcp record to disk
class RECORD_CONTAINER(_NamedTuple):
    '''
    ip:     int
    record: DHCP_RECORD
    '''
    ip:     int
    record: DHCP_RECORD


# SYSLOG CLIENT
SYSLOG_SERVERS = _namedtuple('syslog_servers', 'primary secondary')

# DNS PROXY
DNS_WHITELIST = _namedtuple('whitelist', 'dns')
DNS_BLACKLIST = _namedtuple('blacklist', 'dns')
class DNS_SERVERS(_NamedTuple):  # todo: the typing doesnt seem right here, because union, but maybe its fine.
    '''
    primary:   dict[Union[str, _PROTO], Optional[bool]]
    secondary: dict[Union[str, _PROTO], Optional[bool]]
    '''
    primary:   dict[Union[str, _PROTO], Optional[bool]]
    secondary: dict[Union[str, _PROTO], Optional[bool]]

class RELAY_CONN(_NamedTuple):
    '''
    remote_ip: str
    sock: Socket_T
    send: Callable[[Union[bytes, bytearray]], int]
    recv: Union[Callable[[int], bytes], Callable[[Union[bytearray, memoryview]], int]]
    version: str
    '''
    remote_ip: str
    sock: Socket_T
    send: Callable[[Union[bytes, bytearray]], int]
    recv: Union[Callable[[int], bytes], Callable[[Union[bytearray, memoryview]], int]]
    version: str

class DNS_SEND(_NamedTuple):
    '''
    qname: str
    data:  bytearray
    '''
    qname: str
    data:  bytearray

class QNAME_RECORD(_NamedTuple):
    '''
    expire:  int
    ttl:     int
    records: list[RESOURCE_RECORD]
    '''
    expire:  int
    ttl:     int
    records: list[RESOURCE_RECORD]

class QNAME_RECORD_UPDATE(_NamedTuple):
    '''
    ttl:     int
    records: list[RESOURCE_RECORD]
    '''
    ttl:     int
    records: list[RESOURCE_RECORD]

class DNS_SIGNATURES(_NamedTuple):  # todo: type this out better using NewTypes.
    '''
    filter:  dict[_DNS_CAT, DNS_CAT_LABEL]  # note: trying out new attr name
    tld:     dict[str, int]
    keyword: list[tuple[str, _DNS_CAT]]
    '''
    filter:  dict[_DNS_CAT, DNS_CAT_LABEL]  # note: trying out new attr name
    tld:     dict[str, int]
    keyword: list[tuple[str, _DNS_CAT]]

if (TYPE_CHECKING):
    _DNS_EVENT_CATEGORY: TypeAlias = tuple[DNS_CAT_LABEL, _DNS_CAT, SEC_PROFILE]
class DNS_INSPECTION_RESULTS(_NamedTuple):
    '''
    redirect: bool
    reason:   str
    category: tuple[DNS_CAT_LABEL, _DNS_CAT, SEC_PROFILE]
    '''
    redirect: bool
    reason:   str
    category: _DNS_EVENT_CATEGORY

class DNS_EVENT_LOG(_NamedTuple):
    '''
    timestamp: int
    src_ip:    IP_ADDRINT
    request:   str
    category:  tuple[DNS_CAT_LABEL, _DNS_CAT, SEC_PROFILE]
    reason:    str
    action:    str

    @property
    category_str -> str: category tuple in a db compatible string with "/" separators.

    encode(encoding='utf-8') -> bytes
    '''
    timestamp: int
    src_ip:    IP_ADDRINT
    request:   str
    category:  _DNS_EVENT_CATEGORY  # bookmark:: this will become a tuple of (cat_group, cat_name, sec_profile). prob needs to be a Union with string for DB receiving end.
    reason:    str
    action:    str

    @property
    def category_str(self) -> str:
        return f'{self.category[0]}/{self.category[1].name}/{self.category[2]}'

    def encode(self, encoding='utf-8') -> bytes:
        return f'{self.timestamp},{self.src_ip},{self.request},{self.category_str},{self.reason},{self.action}'.encode(encoding)

# bookmark:: add comments regarding log string joins. consider making formatter method within the class.
# IP PROXY
if (TYPE_CHECKING):
    _IPP_EVENT_CATEGORY: TypeAlias = tuple[GEOLOCATION, REPUTATION, SEC_PROFILE]
class IPP_INSPECTION_RESULTS(_NamedTuple):
    '''
    category: tuple[GEOLOCATION, REPUTATION, SEC_PROFILE]
    action:   _DECISION
    '''
    category: _IPP_EVENT_CATEGORY  # bookmark:: sec_profile should be available still.
    action:   _DECISION

class IPP_EVENT_LOG(_NamedTuple):
    '''
    timestamp:  int
    local_ip:   IP_ADDRINT
    tracked_ip: IP_ADDRINT
    category:   tuple[GEOLOCATION, REPUTATION, SEC_PROFILE]
    direction:  str
    action:     str
    '''
    timestamp:  int
    local_ip:   IP_ADDRINT
    tracked_ip: IP_ADDRINT
    category:   _IPP_EVENT_CATEGORY
    direction:  str
    action:     str

    @property
    def category_str(self) -> str:
        return f'{self.category[0]}/{self.category[1]}/{self.category[2]}'

    def encode(self, encoding='utf-8') -> bytes:
        return f'{self.timestamp},{self.local_ip},{self.tracked_ip},{self.category_str},{self.direction},{self.action}'.encode(encoding)

# IPS/IDS
IPS_WAN_INFO = _namedtuple('ips_wan_info', 'interface ip mac')

class PSCAN_TRACKERS(_NamedTuple):
    '''
    lock:    Lock_T
    tracker: dict[IP_ADDRINT, dict[str, Any]]
    '''
    lock:    Lock_T
    tracker: dict[IP_ADDRINT, dict[str, Any]]

class DDOS_TRACKERS(_NamedTuple):
    '''
    lock:    Lock_T
    tracker: dict[IP_ADDRINT, dict[str, Any]]
    '''
    lock:    Lock_T
    tracker: dict[IP_ADDRINT, dict[str, Any]]

class IPS_SCAN_RESULTS(_NamedTuple):
    '''
    initial_block: bool
    scan_detected: bool
    block_status:  _IPS
    '''
    initial_block: bool
    scan_detected: bool
    block_status:  _IPS

class IPS_EVENT_LOG(_NamedTuple):
    '''
    timestamp:   int
    attacker:    IP_ADDRINT
    protocol:    NETWORK_PROTOCOL
    attack_type: tuple[str, SEC_PROFILE]
    action:      str
    '''
    timestamp:   int
    attacker:    IP_ADDRINT  # idea:: would probably be nice to keep geolocation info of attackers in log.
    protocol:    NETWORK_PROTOCOL
    attack_type: tuple[str, SEC_PROFILE]
    action:      str

    @property
    def attack_type_str(self) -> str:
        return f'{self.attack_type[0]}/{self.attack_type[1]}'

    def encode(self, encoding='utf-8') -> bytes:
        # return f'{self.timestamp},{self.src_ip},{self.request},{self.category_str},{self.reason},{self.action}'.encode(encoding)

        return b'not implemented'

class GEOLOCATION_LOG(_NamedTuple):
    '''GENERAL GEOLOCATION LOG TUPLE.

    provides properties to convert integer values to a std string form.
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
    '''
    timestamp:     int
    client_mac:    str
    src_ip:        int
    detected_host: str
    reason:        _Union[_DNS_EVENT_CATEGORY, _IPP_EVENT_CATEGORY]
    '''
    timestamp:     int
    client_mac:    str
    src_ip:        int
    detected_host: str
    reason:        Union[_DNS_EVENT_CATEGORY, _IPP_EVENT_CATEGORY]

    @property
    def reason_str(self) -> str:
        return f'{self.reason[0]}/{self.reason[1]}/{self.reason[2]}'

    def encode(self, encoding='utf-8') -> bytes:
        return f'{self.timestamp},{self.client_mac},{self.src_ip},{self.detected_host},{self.reason_str}'.encode(encoding)


# alias
DNS_BLOCKED_LOG = DNS_EVENT_LOG

# DATABASE
BLOCKED_DOM = _namedtuple('blocked', 'domain category reason')

# SOCKET
class L_SOCK(_NamedTuple):
    '''
    name:     str
    ip:       int
    socket:   Socket_T
    send:     Callable[[bytes], int]
    sendto:   Callable[[bytes, NET_ADDRESS], int]
    recvfrom: Callable[[bytes], tuple[int, NET_ADDRESS]]
    '''
    name:     str
    ip:       int
    socket:   Socket_T
    send:     Callable[[bytes], int]
    sendto:   Callable[[bytes, NET_ADDRESS], int]
    recvfrom: Callable[[Bytes], tuple[int, NET_ADDRESS]]

class NFQ_SEND_SOCK(_NamedTuple):
    '''
    zone: int
    ip:   int
    sock_sendto: Callable[[bytes, _NET_ADDRESS], int]
    '''
    zone: int
    ip:   int
    sock_sendto: Callable[[bytes, NET_ADDRESS], int]
