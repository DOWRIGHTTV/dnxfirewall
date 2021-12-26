#!/usr/bin/env python3

import binascii

from functools import partial
from random import getrandbits as _randid
from socket import htons, socket, AF_INET, SOCK_RAW
from subprocess import run, CalledProcessError, DEVNULL

from dnx_gentools.def_constants import byte_join, PROTO
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

    sum = 0
    for chunk in chunks:
        sum += chunk[0]

    sum = (sum >> 16) + (sum & 0xffff)
    sum = ~(sum + (sum >> 16)) & 0xffff

    return checksum_pack(sum) if packed else sum

# calculates and return tcp header checksum
def checksum_tcp(data):
    # if data length is odd, this will pad it with 1 byte to complete final chunk
    if (len(data) & 1):
        data += b'\x00'

    # unpacking in chunks of H(short)/ 16 bit/ 2 byte increments in network order
    chunks = checksum_iunpack(data)

    sum = 0
    # loop taking 2 characters at a time
    for chunk in chunks:
        sum += chunk[0]

    sum = ~(sum + (sum >> 16)) & 0xffff

    return htons(sum)

# calculates and return icmp header checksum
def checksum_icmp(data):

    # unpacking in chunks of H(short)/ 16 bit/ 2 byte increments in network order
    chunks = checksum_iunpack(data)

    sum = 0
    for chunk in chunks:
        sum += chunk[0]

    sum = ~(sum + (sum >> 16)) & 0xffff

    # NOTE: does this need to be converted to network order?
    return htons(sum)

def int_to_ipaddr(ip_addr):

    return '.'.join([f'{b}' for b in long_pack(ip_addr)])

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

def parse_query_name(data, dns_query=None, *, qname=False):
    '''parses dns name from sent in data. uses overall dns query to follow pointers. will return
    name and offset integer value if qname arg is True otherwise will only return offset.'''
    offset, contains_pointer, query_name = 0, False, []

    # TODO: this could be problematic since we slice down data. from what i my limited brain understands at the moment,
    #  data should never be an emtpy byte string if non malformed. the last iteration would have a null byte which is
    #  what this condition is actually testing against for when to stop iteration.
    #       // testing suggests this is fine for now
    while data[0]:

        # adding 1 to section_len to account for itself
        section_len, data = data[0], data[1:]

        # pointer value check. this used to be a separate function, but it felt like a waste so merged it.
        # NOTE: is this a problem is we don't pass in the reference query? is it possible for a pointer to be present in
        # cases where this function is used for non primary purposes?
        if (section_len & 192 == 192):

            # calculates the value of the pointer then uses value as original dns query index. this used to be a
            # separate function, but it felt like a waste so merged it. (-12 accounts for header not included)
            data = dns_query[((section_len << 8 | data[0]) & 16383) - 12:]

            contains_pointer = True

        else:
            # name len + integer value of initial length
            offset += section_len + 1 if not contains_pointer else 0

            query_name.append(data[:section_len].decode())

            # slicing out processed section
            data = data[section_len:]

    # increment offset +2 for pointer length or +1 for termination byte if name did not contain a pointer
    offset += 2 if contains_pointer else 1

    # evaluating qname for .local domain or non fqdn
    local_domain = True if len(query_name) == 1 or (query_name and query_name[-1] == 'local') else False

    if (qname):
        return offset, local_domain, '.'.join(query_name)

    return offset, local_domain

def domain_stob(domain_name):
    domain_bytes = byte_join([
        byte_pack(len(part)) + part.encode('utf-8') for part in domain_name.split('.')
    ])

    # root query (empty string) gets eval'd to length 0 and doesnt need a term byte. ternary will add term byte, if the
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

    def ping(target, *, count=1, OSError=OSError):

        icmp = _icmp_header_template()
        icmp.id = _randid(16)

        replies_rcvd = 0
        for i in range(count):

            icmp.sequence = i
            icmp.checksum = checksum_icmp(icmp.assemble())

            try:
                ping_send(icmp.assemble(), (target, 0))
            except OSError:
                pass

            else:
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
