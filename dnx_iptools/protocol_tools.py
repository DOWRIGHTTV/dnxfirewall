#!/usr/bin/env python3

import binascii

from socket import htons
from subprocess import run, CalledProcessError, DEVNULL

from dnx_iptools.def_structs import *
from dnx_gentools.def_constants import byte_join

__all__ = (
    'checksum_icmp', 'checksum_ipv4', 'checksum_tcp', 'int_to_ipaddr',
    'convert_dns_string_to_bytes', 'convert_mac_to_bytes',
    'convert_mac_to_string', 'convert_string_to_bitmap',
    'create_dns_query_header', 'create_dns_response_header',
    'icmp_reachable', 'parse_query_name'
)

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

def convert_mac_to_string(mac_address):
    string_mac = []
    string_mac_append = string_mac.append
    for i in range(0, 12, 2):
        string_mac_append(mac_address[i:i+2])

    return ':'.join(string_mac)

def convert_mac_to_bytes(mac_address):
    return binascii.unhexlify(mac_address.replace(':', ''))

def convert_string_to_bitmap(rule, offset):
    host_hash = hash(rule)

    b_id = int(f'{host_hash}'[:offset])
    h_id = int(f'{host_hash}'[offset:])

    return (b_id, h_id)

def parse_query_name(data, dns_query=None, *, qname=False):
    '''parses dns name from sent in data. uses overall dns query to follow pointers. will return
    name and offset integer value if qname arg is True otherwise will only return offset.'''

    offset, pointer_present = 0, False
    query_name = []
    while True:
        length = data[0]
        if (length == 0):

            if (not pointer_present):
                offset += 1

            break

        # will break on pad or root name lookup
        if (_is_pointer(length)):

            data = dns_query[_calculate_pointer(data[:2]):]
            if (not pointer_present):
                offset += 2

            pointer_present = True
            continue

        if (not pointer_present):
            offset += length + 1 # name len + integer value of initial length

        query_name.append(data[1:1+length].decode())
        data = data[length+1:]

    if (qname):
        return '.'.join(query_name), offset

    return offset

def _is_pointer(data):
    '''returns whether sent in byte is a dns pointer or not.'''

    return 192 & data == 192

def _calculate_pointer(data):
    '''returns the integer value of the sum of 0-15 bits on 2 byte value. the integer value
    represents the string index of place to look for dns data. 12 bytes will be subtracted
    from the result since we are not including dns header in reference data.'''

    return 16383 & short_unpack(data)[0] - 12

def convert_dns_string_to_bytes(domain_name):
    if (not domain_name):
        return b'\x00'

    domain_bytes = []
    db_append = domain_bytes.append
    for part in domain_name.split('.'):
        db_append(byte_pack(len(part)))
        db_append(part.encode('utf-8'))
    else:
        db_append(b'\x00')

    return byte_join(domain_bytes)

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
