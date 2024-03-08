#!/usr/bin/env python3

from __future__ import annotations

import os
import pwd
import shutil

from binascii import unhexlify
from functools import partial
from random import getrandbits
from socket import socket, AF_INET, SOCK_RAW, SCM_CREDENTIALS
from subprocess import run, CalledProcessError, DEVNULL
from typing import NamedTuple

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import USER, RUN_FOREVER, byte_join, fast_time, UINT32_MAX
from dnx_gentools.def_enums import PROTO
from dnx_gentools.file_operations import read_file

from dnx_iptools.def_structs import *
from dnx_iptools.def_structures import PR_ICMP_HDR
from dnx_iptools.cprotocol_tools import calc_checksum, itoip, hextoip

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools import Structure_T

__all__ = (
    'btoia',  # 'itoba',

    'change_socket_owner', 'authenticate_sender',
    'icmp_reachable',

    'cidrtoi',
    'domain_stob', 'mac_stob',
    'mac_add_sep', 'strtobit',
    'create_dns_query_header',
    'parse_query_name',

    'Route', 'get_routing_table',
)

btoia: Callable[[ByteString|int], int] = partial(int.from_bytes, byteorder='big', signed=False)
# itoba: Callable[[int, int], bytes] = partial(int.to_bytes, byteorder='big', signed=False)


class Route(NamedTuple):
    intf: str
    net_id: str
    cidr: str
    gateway: str
    ad: int

    def __str__(self) -> str:
        '''format -> S        10.1.1.0/24 [90/2170112] via 69.69.69.69, Serial0/0/0
        '''
        gateway = 'Connected' if self.state == 'C' else self.gateway

        state = self.state.ljust(7)
        network = f'{self.net_id}/{self.cidr}'.ljust(18)
        ad = f'[{self.ad}]'.rjust(5)
        gateway = gateway.ljust(15)

        return f'{state} {network} {ad} via {gateway} {self.intf}'

    @property
    def state(self) -> str:

        if (self.gateway == '0.0.0.0'): state_str = 'C'
        else: state_str = 'S'

        if (self.cidr == '32'): state_str += '(H)'
        elif (self.net_id == '0.0.0.0' and self.cidr == '0'): state_str += '(D)'

        return state_str


def mac_add_sep(mac_address: str, sep: str = ':') -> str:
    string_mac = []
    string_mac_append = string_mac.append
    for i in range(0, 12, 2):
        string_mac_append(mac_address[i:i+2])

    return sep.join(string_mac)

def mac_stob(mac_address: str) -> bytes:

    return unhexlify(mac_address.replace(':', ''))

def strtobit(rule: str) -> int:

    return hash(rule) & UINT32_MAX

def cidrtoi(cidr: Union[str, int]) -> int:

    # using hostmask to shift to the start of network bits. int conversion to cover string values.
    hostmask: int = 32 - int(cidr)

    return ~((1 << hostmask) - 1) & (2**32 - 1)


# _CIDR_MAP = {
#     '255.255.255.0'  : '24', '255.255.255.128': '25', '255.255.255.192': '26',
#     '255.255.255.224': '27', '255.255.255.240': '28', '255.255.255.248': '29',
#     '255.255.255.252': '30', '255.255.255.254': '31', '255.255.255.255': '32'
# }
# def masktocidr(netmask: str) -> str:
#     return _CIDR_MAP[netmask]

def masktocidr(netmask: str) -> str:
    x = [bin(int(octet)).count('1') for octet in netmask.split('.')]

    return str(sum(x))

def get_routing_table() -> list[Route]:
    routing_table = []

    routes = read_file('/proc/net/route')

    for line in routes.splitlines()[1:]:
        line = line.split()

        intf = line[0]
        network = hextoip(line[1])
        netmask = hextoip(line[7])
        gateway = hextoip(line[2])
        ad = int(line[6])

        route = Route(intf, network, masktocidr(netmask), gateway, ad)

        routing_table.append(route)

    return routing_table

# =====================
# DNS related functions
# =====================
def domain_stob(domain_name: str) -> bytes:
    domain_bytes = byte_join([
        byte_pack(len(part)) + part.encode('utf-8') for part in domain_name.split('.')
    ])

    # root query (empty string) gets eval'd to length 0 and doesn't need a term byte.
    # ternary will add term byte if the omain name is not a null value.
    return domain_bytes + b'\x00' if domain_name else domain_bytes

# will create dns header specific to request/query. default resource record count is 1, additional record count optional
def create_dns_query_header(dns_id, arc=0, *, cd):

    bit_fields = (1 << 8) | (cd << 4)

    return dns_header_pack(dns_id, bit_fields, 1, 0, 0, arc)

def parse_query_name(data: Union[bytes, memoryview], offset: int = 0, *,
                     quick: bool = False) -> Union[int, tuple[int, str, bool]]:
    '''parse dns name from sent in data.

    if quick is set, returns offset only, otherwise offset, qname decoded, and whether its local domain is returned.
    '''
    idx: int = offset
    has_ptr: bool = False
    label_ct: int = 0
    query_name: bytearray = bytearray()

    for _ in RUN_FOREVER:

        label_len, label_ptr = data[idx], data[idx+1:]

        # root/ null terminated
        if (label_len == 0):
            break

        # std label
        elif (label_len < 64):
            query_name += bytes(label_ptr[:label_len]) + b'.'
            label_ct += 1

            if (not has_ptr):
                offset += label_len + 1

            idx += label_len + 1

        # label ptr
        elif (label_len >= 192):

            # calculates ptr/idx of label (-12 for missing header)
            idx = ((label_len << 8 | label_ptr[0]) & 16383) - 12

            # this ensures standard label parsing won't inc offset
            has_ptr = True

        else:
            raise ValueError('invalid label found in dns record.')

    # offset +2 for ptr or +1 for root
    offset += 2 if has_ptr else 1

    if (quick):
        return offset

    return offset, query_name[:-1].decode(), label_ct == 1

# ======================
# ICMP related functions
# ======================
# will ping specified host. to be used to prevent duplicate ip address handouts.
def icmp_reachable(host_ip: int) -> bool:

    try:
        return bool(run(f'ping -c 2 {itoip(host_ip)}', stdout=DEVNULL, shell=True, check=True))
    except CalledProcessError:
        return False


icmp_header_template: Structure_T = PR_ICMP_HDR((('type', 8), ('code', 0)))

def init_ping(timeout: float = .25) -> Callable[[str, int], bool]:
    '''function factory that returns a ping function object optimized for speed.

    not thread safe within a single ping object, but is thread safe between multiple ping objects.
    '''
    ping_sock = socket(AF_INET, SOCK_RAW, PROTO.ICMP)
    ping_sock.settimeout(timeout)

    ping_send = ping_sock.sendto
    ping_recv = ping_sock.recvfrom

    def ping(target: str, *, count: int = 1, ose=OSError) -> bool:

        icmp = icmp_header_template()
        icmp.id = getrandbits(16)

        replies_rcvd = 0
        for i in range(count):

            icmp.sequence = i
            icmp.checksum = btoia(calc_checksum(icmp.assemble()))

            ping_send(icmp.assemble(), (target, 0))

            recv_start = fast_time()

            for _ in RUN_FOREVER:
                try:
                    echo_reply, addr = ping_recv(2048)
                except ose:
                    break

                else:
                    # checking overall recv time passed for each ping send.
                    if (fast_time() - recv_start > timeout):
                        break

                    iphdr_len = (echo_reply[0] & 15) * 4

                    type, code, checksum, id, seq = icmp_header_unpack(echo_reply[iphdr_len:])
                    if (type == 0 and id == icmp.id and i == seq):
                        replies_rcvd += 1

                        break

            # need to reset if doing more than 1 echo request. figure out a way to skip if only doing 1.
            icmp.checksum = 0

        return replies_rcvd/count > .5

    return ping

# =======================================
# SOCKET RELATED FUNCTIONS
# =======================================
def change_socket_owner(sock_path: str) -> bool:
    '''attempts to change the file owner and permissions of the passed in socket to dnx/dnx.

    following the change, the permissions will be set to 660.
    return True on success, False on failure.

        required: run on unix sockets created by root.
        optional: run on unix socket created by dnx (would only slightly reduce permissions)
    '''
    try:
        shutil.chown(sock_path, user='dnx', group='dnx')
        os.chmod(sock_path, 0o660)
    except PermissionError:
        return False

    return True

# SERVICE SOCKET - Auth Validation
_getuser_info = pwd.getpwuid
_getuser_groups = os.getgrouplist
def authenticate_sender(anc_data: Iterable[tuple[int, int, bytes]]) -> bool:
    anc_data = {msg_type: data for _, msg_type, data in anc_data}

    auth_data = anc_data.get(SCM_CREDENTIALS)
    if (not auth_data):
        return False

    pid, uid, gid = scm_creds_unpack(auth_data)
    # USER is a dnxfirewall constant specified in def_constants
    if (_getuser_info(uid).pw_name != USER):
        return False

    return True
