#!/usr/bin/env python3

import binascii

from functools import partial
from random import getrandbits
from socket import htons, socket, AF_INET, SOCK_RAW
from subprocess import run, CalledProcessError, DEVNULL

from dnx_gentools.def_constants import RUN_FOREVER, PROTO, byte_join, dot_join
from dnx_iptools.def_structs import *
from dnx_iptools.def_structures import PR_ICMP_HDR

__all__ = (
    'btoia', 'itoba',

    'icmp_reachable',

    'checksum_icmp', 'checksum_ipv4', 'checksum_tcp',
    'int_to_ipaddr', 'domain_stob', 'mac_stob',
    'mac_add_sep', 'convert_string_to_bitmap',
    'create_dns_query_header', 'create_dns_response_header',
    'parse_query_name'
)

btoia = partial(int.from_bytes, byteorder='big', signed=False)
itoba = partial(int.to_bytes, byteorder='big', signed=False)

# will ping specified host. to be used to prevent duplicate ip address handouts.
def icmp_reachable(host_ip):
    try:
        return run(f'ping -c 2 {host_ip}', stdout=DEVNULL, shell=True, check=True)
    except CalledProcessError:
        return False

# calculates and returns ipv4 header checksum
def checksum_ipv4(data, packed=False):

    # unpacking in chunks of H(short)/ 16 bit/ 2 byte increments in network order
    chunks = checksum_iunpack(data)

    csum = 0
    for chunk in chunks:
        csum += chunk[0]

    csum = (csum >> 16) + (csum & 0xffff)
    csum = ~(csum + (csum >> 16)) & 0xffff

    return checksum_pack(csum) if packed else csum

# calculates and return tcp header checksum
def checksum_tcp(data):
    # if data length is odd, this will pad it with 1 byte to complete final chunk
    if (len(data) & 1):
        data += b'\x00'

    # unpacking in chunks of H(short)/ 16 bit/ 2 byte increments in network order
    chunks = checksum_iunpack(data)

    csum = 0
    # loop taking 2 characters at a time
    for chunk in chunks:
        csum += chunk[0]

    csum = ~(csum + (csum >> 16)) & 0xffff

    return htons(csum)

# calculates and return icmp header checksum
# TODO: why is this identical to tcp?
def checksum_icmp(data):

    # unpacking in chunks of H(short)/ 16 bit/ 2 byte increments in network order
    chunks = checksum_iunpack(data)

    csum = 0
    for chunk in chunks:
        csum += chunk[0]

    csum = ~(csum + (csum >> 16)) & 0xffff

    # NOTE: does this need to be converted to network order?
    return htons(csum)

def int_to_ipaddr(ip_addr):

    return dot_join([f'{b}' for b in long_pack(ip_addr)])

def mac_add_sep(mac_address, sep=':'):
    string_mac = []
    string_mac_append = string_mac.append
    for i in range(0, 12, 2):
        string_mac_append(mac_address[i:i+2])

    return sep.join(string_mac)

def mac_stob(mac_address):

    return binascii.unhexlify(mac_address.replace(':', ''))

def convert_string_to_bitmap(rule, offset):
    host_hash = hash(rule)

    b_id = int(f'{host_hash}'[:offset])
    h_id = int(f'{host_hash}'[offset:])

    return (b_id, h_id)

def cidr_to_int(cidr):

    # using hostmask to shift to the start of network bits
    hostmask = 32 - cidr

    return ~((1 << hostmask) - 1) & (2**32 - 1)

def parse_query_name(data, offset=0, *, qname=False):
    '''parses dns name from sent in data. uses overall dns query to follow pointers. will return
    name and offset integer value if qname arg is True otherwise will only return offset.'''

    label_ct = 0
    query_name = bytearray()

    for _ in RUN_FOREVER():

        data_ptr = data[offset:]

        # root domain/ null terminated
        if (not data_ptr[0]):
            break

        # label ptr check
        if (data_ptr & 192 == 192):

            # calculates dns ptr value then uses dns payload slice index. (-12 accounts for header not included)
            label_ptr = data[(short_unpackf(data_ptr)[0] & 16383) - 12:]

            query_name += label_ptr[1:label_ptr[0] + 1]
            query_name += b'.'

            offset += 2

        # standard label
        else:
            # used to identify local domains
            label_ct += 1

            query_name += data_ptr[1:data_ptr[0] + 1]
            query_name += b'.'

            offset += data_ptr[0] + 1

    # increment offset +1 for termination byte. see if this can be moved
    offset += 1

    if (qname):
        return offset, (query_name[:-1].decode(), label_ct == 1)

    return offset

def domain_stob(domain_name):
    domain_bytes = byte_join([
        byte_pack(len(part)) + part.encode('utf-8') for part in domain_name.split('.')
    ])

    # root query (empty string) gets eval'd to length 0 and doesn't need a term byte. ternary will add term byte, if the
    # domain name is not a null value.
    return domain_bytes + b'\x00' if domain_name else domain_bytes

# will create dns header specific to response. default resource record count is 1
def create_dns_response_header(dns_id, record_count=1, *, rd=1, ad=0, cd=0, rc=0):
    qr, op, aa, tc, ra, zz = 1,0,0,0,1,0
    f = (qr << 15) | (op << 11) | (aa << 10) | (tc << 9) | (rd << 8) | \
        (ra <<  7) | (zz <<  6) | (ad <<  5) | (cd << 4) | (rc << 0)

    return dns_header_pack(dns_id, f, 1, record_count, 0, 0)

# will create dns header specific to request/query. default resource record count is 1, additional record count optional
def create_dns_query_header(dns_id, arc=0, *, cd):
    qr, op, aa, tc, rd, ra, zz, ad, rc = 0,0,0,0,1,0,0,0,0
    f = (qr << 15) | (op << 11) | (aa << 10) | (tc << 9) | (rd << 8) | \
        (ra <<  7) | (zz <<  6) | (ad <<  5) | (cd << 4) | (rc << 0)

    return dns_header_pack(dns_id, f, 1, 0, 0, arc)


_icmp_header_template = PR_ICMP_HDR(**{'type': 8, 'code': 0})

def init_ping(timeout=.25):
    '''function factory that returns a ping function object optimized for speed. not thread safe within a single ping
     object, but is thread safe between multiple ping objects.'''

    ping_sock = socket(AF_INET, SOCK_RAW, PROTO.ICMP)
    ping_sock.settimeout(timeout)

    ping_send = ping_sock.sendto
    ping_recv = ping_sock.recvfrom

    _randid = getrandbits
    _range = range

    def ping(target, *, count=1, OSError=OSError):

        icmp = _icmp_header_template()
        icmp.id = _randid(16)

        replies_rcvd = 0
        for i in _range(count):

            icmp.sequence = i
            icmp.checksum = checksum_icmp(icmp.assemble())

            try:
                ping_send(icmp.assemble(), (target, 0))
            except OSError:
                pass

            else:
                # TODO: this might need a mechanism to break if we don't receive a matching response after X reads.
                while True:
                    try:
                        echo_reply, addr = ping_recv(2048)
                    except OSError:
                        pass

                    else:
                        iphdr_len = (echo_reply[0] & 15) * 4

                        type, code, checksum, id, seq = icmp_header_unpack(echo_reply[iphdr_len:])
                        if (type == 0 and id == icmp.id and i == seq):
                            replies_rcvd += 1

                            break

            # need to reset if doing more than 1 echo request. figure out a way to skip if only doing 1.
            icmp.checksum = 0

        return replies_rcvd/count > .5

    return ping
