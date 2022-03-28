#!/usr/bin/env python3

from __future__ import annotations

import binascii

from functools import partial
from random import getrandbits
from socket import socket, inet_aton, AF_INET, SOCK_RAW
from subprocess import run, CalledProcessError, DEVNULL

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import RUN_FOREVER, byte_join, dot_join, fast_time, UINT32_MAX
from dnx_gentools.def_enums import PROTO
from dnx_iptools.def_structs import *
from dnx_iptools.def_structures import PR_ICMP_HDR

__all__ = (
    'btoia', 'itoba',

    'icmp_reachable',

    'itoip', 'iptoi', 'cidr_to_int',
    'domain_stob', 'mac_stob',
    'mac_add_sep', 'strtobit',
    'create_dns_query_header', 'create_dns_response_header',
    'parse_query_name', 'mhash'
)

btoia: Callable[[ByteString], int] = partial(int.from_bytes, byteorder='big', signed=False)
itoba: Callable[[int, int], bytes] = partial(int.to_bytes, byteorder='big', signed=False)

# will ping specified host. to be used to prevent duplicate ip address handouts.
def icmp_reachable(host_ip: str) -> bool:
    try:
        return bool(run(f'ping -c 2 {host_ip}', stdout=DEVNULL, shell=True, check=True))
    except CalledProcessError:
        return False

def itoip(ip: int, /) -> str:

    return dot_join([f'{b}' for b in long_pack(ip)])

def iptoi(ip: str, /) -> int:

    return btoia(inet_aton(ip))

def mac_add_sep(mac_address: str, sep: str = ':') -> str:
    string_mac = []
    string_mac_append = string_mac.append
    for i in range(0, 12, 2):
        string_mac_append(mac_address[i:i+2])

    return sep.join(string_mac)

def mac_stob(mac_address: str) -> bytes:

    return binascii.unhexlify(mac_address.replace(':', ''))

def strtobit(rule: str) -> int:
    host_hash = hash(rule) & UINT32_MAX

    return host_hash

def cidr_to_int(cidr: Union[str, int]) -> int:

    # using hostmask to shift to the start of network bits. int conversion to cover string values.
    hostmask: int = 32 - int(cidr)

    return ~((1 << hostmask) - 1) & (2**32 - 1)

def parse_query_name(data: Union[bytes, memoryview], offset: int = 0, *,
                     quick: bool = False) -> Union[int, tuple[int, str, bool]]:
    '''parse dns name from sent in data.

    if quick is set, returns offset only, otherwise offset, qname decoded, and whether its local domain.
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

def mhash(key: str, seed: int = 0x0):
    '''Implements 32bit murmur3 hash.
    '''
    bkey = bytearray(key.encode('utf-8'))

    length:  int = len(key)
    nblocks: int = length // 4

    h1: int = seed

    c1: int = 0xcc9e2d51
    c2: int = 0x1b873593

    k1: int
    for block_start in range(0, nblocks * 4, 4):
        k1 = (bkey[block_start + 3] << 24 | bkey[block_start + 2] << 16 |
              bkey[block_start + 1] << 8  | bkey[block_start + 0])

        k1 = (c1 * k1) & 0xFFFFFFFF
        k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF  # inlined ROTL32
        k1 = (c2 * k1) & 0xFFFFFFFF

        h1 ^= k1
        h1 = (h1 << 13 | h1 >> 19) & 0xFFFFFFFF  # inlined ROTL32
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    k2: int = 0
    tail_index: int = nblocks * 4
    tail_size: int = length & 3

    if (tail_size >= 3):
        k2 ^= bkey[tail_index + 2] << 16

    if (tail_size >= 2):
        k2 ^= bkey[tail_index + 1] << 8

    if (tail_size >= 1):
        k2 ^= bkey[tail_index + 0]

    if (tail_size > 0):
        k2 = (k2 * c1) & 0xFFFFFFFF
        k2 = (k2 << 15 | k2 >> 17) & 0xFFFFFFFF  # inlined ROTL32
        k2 = (k2 * c2) & 0xFFFFFFFF
        h1 ^= k2

    # FINAL MIX
    h = h1 ^ length
    h ^= h >> 16
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= h >> 16
    unsigned_val = h

    if (not unsigned_val & 0x80000000):
        return unsigned_val

    else:
        return -((unsigned_val ^ 0xFFFFFFFF) + 1)


icmp_header_template: Structure = PR_ICMP_HDR((('type', 8), ('code', 0)))

def init_ping(timeout: float = .25) -> Callable[[str, int], bool]:
    '''function factory that returns a ping function object optimized for speed.

    not thread safe within a single ping object, but is thread safe between multiple ping objects.'''

    ping_sock = socket(AF_INET, SOCK_RAW, PROTO.ICMP)
    ping_sock.settimeout(timeout)

    ping_send = ping_sock.sendto
    ping_recv = ping_sock.recvfrom

    def ping(target: str, *, count: int = 1, ose=OSError) -> bool:

        icmp = icmp_header_template()
        icmp.id = getrandbits(16)

        replies_rcvd = 0
        for i in range(count):

            # NOTE: this is dumb. should only call assemble once.
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
                    # this covers cases where unrelated ping responses are received that
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
