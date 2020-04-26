#!/usr/bin/env python3

import os, sys
import array
import struct
import binascii

from subprocess import run, CalledProcessError, DEVNULL

_HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, _HOME_DIR)

from dnx_iptools.dnx_structs import * # pylint: disable=unused-wildcard-import

__all__ = (
    'checksum_dnx', 'checksum_icmp', 'checksum_ipv4', 'checksum_tcp',
    'convert_dns_string_to_bytes', 'convert_mac_to_bytes',
    'convert_mac_to_string', 'convert_string_to_bitmap',
    'create_dns_query_header', 'create_dns_response_header',
    'create_dnx_proto_packet', 'icmp_reachable', 'parse_query_name'
)

# will ping specified host. to be used to prevent duplicate ip address handouts.
def icmp_reachable(host_ip):
    try:
        return run(f'ping -c 2 {host_ip}', stdout=DEVNULL, shell=True, check=True)
    except CalledProcessError:
        return False

# calculates and returns ipv4 header checksum
def checksum_ipv4(header):
    if (len(header) & 1):
        header = header + '\0'
    words = array.array('h', header)

    sum = 0
    for word in words:
        sum = sum + (word & 0xffff)

    hi  = sum >> 16
    lo  = sum & 0xffff
    sum = hi + lo
    sum = sum + (sum >> 16)

    return checksum_pack((~sum) & 0xffff)

# calculates and return tcp header checksum
def checksum_tcp(msg):
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        if ((i+1) < len(msg)):
            a = msg[i]
            b = msg[i+1]
            s = s + (a+(b << 8))

        elif ((i+1) == len(msg)):
            s += msg[i]

    s = s + (s >> 16)
    s = ~s & 0xffff

    return checksum_pack(s)

# calculates and return icmp header checksum
def checksum_icmp(msg):
    s = 0
    while msg:
        s  += (msg[0] + (msg[1] << 8))
        msg = msg[2:]

    s += (s >> 16)
    s  = ~s & 0xffff

    return checksum_pack(s)

def convert_mac_to_string(mac_address):
    string_mac = []
    while mac_address:
        string_mac.append(mac_address[:2])
        mac_address = mac_address[2:]

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
        if (length == 0): # not length?
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
            offset += length + 1 # name len + interger value of initial length

        query_name.append(data[1:1+length].decode())
        data = data[length+1:]

    if (qname):
        return '.'.join(query_name), offset

    return offset

def _is_pointer(data):
    return True if 192 & data == 192 else False

def _calculate_pointer(data):
    '''returns the integer value of the sum of 0-15 bits on 2 byte value. the integer value
    represents the string index of place to look for dns data. 12 bytes will be subtracted
    from the result since we are not including dns header in reference data.'''
    return 16383 & short_unpack(data)[0] - 12

def convert_dns_string_to_bytes(domain_name):
    if (not domain_name):
        return b'\x00'

    split_domain = domain_name.split('.')
    domain_bytes = []
    for part in split_domain:
        domain_bytes.append(byte_pack(len(part)))
        domain_bytes.append(part.encode('utf-8'))
    else:
        domain_bytes.append(b'\x00')

    return b''.join(domain_bytes)

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

