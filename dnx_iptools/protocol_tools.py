#!/usr/bin/env python3

from __future__ import annotations

import binascii

from functools import partial
from random import getrandbits
from socket import socket, htons, inet_aton, AF_INET, SOCK_RAW
from subprocess import run, CalledProcessError, DEVNULL

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import RUN_FOREVER, byte_join, dot_join, fast_time
from dnx_gentools.def_enums import PROTO
from dnx_iptools.def_structs import *
from dnx_iptools.def_structures import PR_ICMP_HDR

__all__ = (
    'btoia', 'itoba',

    'icmp_reachable',

    'calc_checksum',
    'int_to_ip', 'ip_to_int', 'cidr_to_int',
    'domain_stob', 'mac_stob',
    'mac_add_sep', 'convert_string_to_bitmap',
    'create_dns_query_header', 'create_dns_response_header',
    'parse_query_name'
)

btoia: Callable[[Union[bytes, bytearray, memoryview]], int] = partial(int.from_bytes, byteorder='big', signed=False)
itoba: Callable[[int, int], bytes] = partial(int.to_bytes, byteorder='big', signed=False)

# will ping specified host. to be used to prevent duplicate ip address handouts.
def icmp_reachable(host_ip: str) -> bool:
    try:
        return bool(run(f'ping -c 2 {host_ip}', stdout=DEVNULL, shell=True, check=True))
    except CalledProcessError:
        return False

def calc_checksum(data: Union[bytes, bytearray], pack: bool = False) -> Union[int, bytes]:
    # if data length is odd, this will pad it with 1 byte to complete final chunk
    if (len(data) & 1):
        data += b'\x00'

    # unpacking in chunks of H(short)/ 16 bit/ 2 byte increments in < order
    chunks: Iterator[tuple[int]] = checksum_iunpack(data)

    csum: int = 0
    # loop taking 2 characters at a time
    for chunk in chunks:
        csum += chunk[0]

    # fold 32-bit sum to 16 bits (x2) then bitwise NOT for inverse
    csum = (csum >> 16) + (csum & 65535)
    csum += (csum >> 16)

    return checksum_pack(~csum) if pack else htons(~csum)

def int_to_ip(ip: int, /) -> str:

    return dot_join([f'{b}' for b in long_pack(ip)])

def ip_to_int(ip: str, /) -> int:

    return btoia(inet_aton(ip))

def mac_add_sep(mac_address: str, sep: str = ':') -> str:
    string_mac = []
    string_mac_append = string_mac.append
    for i in range(0, 12, 2):
        string_mac_append(mac_address[i:i+2])

    return sep.join(string_mac)

def mac_stob(mac_address: str) -> bytes:

    return binascii.unhexlify(mac_address.replace(':', ''))

def convert_string_to_bitmap(rule: str, offset: int) -> tuple[int, int]:
    host_hash: hash = hash(rule)

    b_id: int = int(f'{host_hash}'[:offset])
    h_id: int = int(f'{host_hash}'[offset:])

    return b_id, h_id

def cidr_to_int(cidr: int) -> int:

    # using hostmask to shift to the start of network bits. int conversion to cover string values.
    hostmask: int = 32 - int(cidr)

    return ~((1 << hostmask) - 1) & (2**32 - 1)

def parse_query_name(data: Union[bytes, memoryview], offset: int = 0, *,
                     qname: bool = False) -> Union[int, tuple[int, tuple[str, int]]]:
    '''parse dns name from sent in data. uses overall dns query to follow pointers. will return
    name and offset integer value if qname arg is True otherwise will only return offset.'''

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

    if (qname):
        return offset, (query_name[:-1].decode(), label_ct == 1)

    return offset

def domain_stob(domain_name: str) -> bytes:
    domain_bytes = byte_join([
        byte_pack(len(part)) + part.encode('utf-8') for part in domain_name.split('.')
    ])

    # root query (empty string) gets eval'd to length 0 and doesn't need a term byte. ternary will add term byte if the
    # domain name is not a null value.
    return domain_bytes + b'\x00' if domain_name else domain_bytes

# will create dns header specific to response. default resource record count is 1
def create_dns_response_header(dns_id, record_count=1, *, rd=1, ad=0, cd=0, rc=0):

    qr, op, aa, tc, ra, zz = 1, 0, 0, 0, 1, 0
    f = (qr << 15) | (op << 11) | (aa << 10) | (tc << 9) | (rd << 8) | \
        (ra <<  7) | (zz <<  6) | (ad <<  5) | (cd << 4) | (rc << 0)

    return dns_header_pack(dns_id, f, 1, record_count, 0, 0)

# will create dns header specific to request/query. default resource record count is 1, additional record count optional
def create_dns_query_header(dns_id, arc=0, *, cd):

    qr, op, aa, tc, rd, ra, zz, ad, rc = 0, 0, 0, 0, 1, 0, 0, 0, 0
    f = (qr << 15) | (op << 11) | (aa << 10) | (tc << 9) | (rd << 8) | \
        (ra <<  7) | (zz <<  6) | (ad <<  5) | (cd << 4) | (rc << 0)

    return dns_header_pack(dns_id, f, 1, 0, 0, arc)


_icmp_header_template = PR_ICMP_HDR(**{'type': 8, 'code': 0})

def init_ping(timeout: float = .25) -> Callable[[str, int], bool]:
    '''function factory that returns a ping function object optimized for speed.

    not thread safe within a single ping object, but is thread safe between multiple ping objects.'''

    ping_sock = socket(AF_INET, SOCK_RAW, PROTO.ICMP)
    ping_sock.settimeout(timeout)

    ping_send = ping_sock.sendto
    ping_recv = ping_sock.recvfrom

    def ping(target: str, *, count: int = 1, ose=OSError) -> bool:

        icmp = _icmp_header_template()
        icmp.id = getrandbits(16)

        replies_rcvd = 0
        for i in range(count):

            icmp.sequence = i
            icmp.checksum = calc_checksum(icmp.assemble())

            ping_send(icmp.assemble(), (target, 0))

            recv_start = fast_time()

            for _ in RUN_FOREVER:
                try:
                    echo_reply, addr = ping_recv(2048)
                except ose:
                    break

                else:

                    # checking overall recv time passed for each ping send. this covers cases where unrelated ping
                    # responses are received that
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
