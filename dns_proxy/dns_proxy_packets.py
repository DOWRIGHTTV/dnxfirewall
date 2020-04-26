#!/usr/bin/env python3

import os, sys
import time
import struct
import traceback

from socket import inet_aton
from collections import namedtuple
from ipaddress import IPv4Address

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_iptools.dnx_interface as interface

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_structs import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_protocol_tools import * # pylint: disable=unused-wildcard-import
from dnx_configure.dnx_namedtuples import RESOURCE_RECORD, CACHED_RECORD
from dnx_iptools.dnx_parent_classes import RawPacket


class ClientRequest:
    __slots__ = (
        # protected vars
        '_data', '_dns_header', '_dns_query',

        # public vars - init
        'address', 'sock', 'intf', 'top_domain',
        'keepalive', 'dom_local', 'fallback',
        'dns_id', 'request', 'send_data',
        'arc', 'additional_data',

        # public vars - dns
        'qr', 'op', 'aa', 'tc', 'rd',
        'ra', 'zz', 'ad', 'cd', 'rc',

        'requests', 'qtype', 'qclass', 'question_record'
    )

    def __init__(self, data, address, sock_info):
        self._data   = data
        self.address = address
        if (data):
            self._dns_header = data[:12]
            self._dns_query  = data[12:]
        if (sock_info):
            self.sock, self.intf = sock_info
        self.top_domain = False if address[0] else True

        self.keepalive = False
        self.dom_local = False
        self.fallback  = False

        self.dns_id    = 1
        self.request   = None
        self.send_data = b''

        # OPT record defaults
        self.arc = 0
        self.additional_data = b''

    def __str__(self):
        return f'dns_query(host={self.address[0]}, port={self.address[1]}, request={self.request})'

    def parse(self):
        if (not self._data):
            raise TypeError(f'{__class__.__name__} cannot parse data set to None.')

        self._parse_header()
        self._parse_dns_query()

    # TODO: see if we should validate whether there is an indicated question record before continuing
    def _parse_header(self):
        dns_header = dns_header_unpack(self._dns_header)
        self.dns_id = dns_header[0]
        self.qr = dns_header[1] >> 15 & 1
        self.op = dns_header[1] >> 11 & 15
        self.aa = dns_header[1] >> 10 & 1
        self.tc = dns_header[1] >> 9  & 1
        self.rd = dns_header[1] >> 8  & 1
        self.ra = dns_header[1] >> 7  & 1
        self.zz = dns_header[1] >> 6  & 1
        self.ad = dns_header[1] >> 5  & 1
        self.cd = dns_header[1] >> 4  & 1
        self.rc = dns_header[1]       & 15

    def _parse_dns_query(self):
        dns_query = self._dns_query
        request, offset = parse_query_name(dns_query, qname=True) # www.micro.com or micro.com || sd.micro.com
        # will prevent local records from getting external resolved
        if ('.' not in request):
            self.dom_local = True

        self.request = request

        self.qtype, self.qclass = double_short_unpack(dns_query[offset:])
        self.question_record = dns_query[:offset+4] # ofsset + 4 byte info
        self.additional_data = dns_query[offset+4:]

    def generate_record_response(self, host_ip=None, configured_ttl=THIRTY_MIN):
        '''builds a dns server response for locally configured records. if no record is found, an empty
        response (no resource record) will be generated.'''
        if (self.send_data):
            raise RuntimeWarning('send data has already been created for this query.')

        send_data = [
            create_dns_response_header(self.dns_id, rd=self.rd, cd=self.cd
        )]
        send_data.append(self.question_record)
        if (host_ip):
            send_data.append(resource_record_pack(
                49164, 1, 1, configured_ttl, 4, inet_aton(host_ip)
            ))

        self.send_data = b''.join(send_data)

    def generate_cached_response(self, cached_dom):
        if (self.send_data):
            raise RuntimeWarning('send data has already been created for this query.')

        send_data = [create_dns_response_header(
            self.dns_id, len(cached_dom.records), rd=self.rd, cd=self.cd
        )]
        send_data.append(self.question_record)
        for record in cached_dom.records:
            record.update('ttl', long_pack(cached_dom.ttl))
            send_data.append(b''.join(record))

        self.send_data = b''.join(send_data)

    def generate_dns_query(self, dns_id, protocol):
        if (self.send_data):
            raise RuntimeWarning('send data has already been created for this query.')

        # if additional data seen after question record, will mark additional record count as 1 in dns header
        if (self.additional_data):
            self.arc = 1
        # TODO: see what the list bounds are for having to resize. if the header + length fits, we can remove
        # the pre assignment length bytes. make sure insert scenario is looked at.
        send_data = [b'\x00\x00', create_dns_query_header(dns_id, self.arc, cd=self.cd)]
        send_data.append(convert_dns_string_to_bytes(self.request))
        send_data.append(double_short_pack(self.qtype, 1))
        send_data.append(self.additional_data)

        if (protocol == PROTO.DNS_TLS):
            send_data[0] = short_pack(len(b''.join(send_data[1:])))
        else:
            send_data.pop(0)

        self.send_data = b''.join(send_data)

    @classmethod
    def generate_local_query(cls, request, cd=1):
        '''alternate constructor for creating locally generated queries (top domains).'''

        self = cls(None, NULL_ADDR, None)
        # harcorded qtype can change if needed.
        self.request   = request
        self.qtype     = 1
        self.cd        = cd

        return self

    @classmethod
    def generate_keepalive(cls, request, protocol, cd=1):
        '''alternate construct for creating locally generated keep alive queries.'''
        self = cls(None, NULL_ADDR, None)
        # harcorded qtype can change if needed.
        self.request   = request
        self.qtype     = 1
        self.cd        = cd

        self.generate_dns_query(DNS.KEEPALIVE, protocol)

        return self


class ProxyRequest(RawPacket):
    __slots__ = (
        #protected vars
        '_dns_header', '_dns_query',

        # public vars
        'request', 'requests', 'client_address', 'dom_local',
        'qtype', 'qclass', 'dns_id', 'question_record',

        'qr', '_rd', '_cd', 'send_data'
    )

    def __init__(self):
        super().__init__()

        self.qr     = None
        self.qtype  = None
        self.qclass = None

    @property
    def continue_condition(self):
        if (self.protocol == PROTO.UDP):
            return True

        return False

    # extension from parent class.
    def _before_exit(self):
        self._dns_header = self.udp_payload[:12]
        self._dns_query  = self.udp_payload[12:]

        if (self.dst_port == PROTO.DNS):
            self._header()
            if (self.qr == DNS.QUERY):
                self._query()

        self.client_address = (f'{self.src_ip}', self.src_port)

    # dns header
    def _header(self):
        dns_header = dns_header_unpack(self._dns_header)
        self.dns_id = dns_header[0]
        self.qr  = dns_header[1] >> 15 & 1
        self._rd = dns_header[1] >> 8  & 1
        self._cd = dns_header[1] >> 4  & 1

    # dns query
    def _query(self):
        dns_query = self._dns_query
        self.request, offset = parse_query_name(dns_query, qname=True) # www.micro.com or micro.com || sd.micro.com

        self.requests = self._enumerate_request(self.request)

        self.qtype, self.qclass = double_short_unpack(dns_query[offset:])
        self.question_record = dns_query[:offset+4] # ofsset + 4 byte info

    # will create send data object for used by proxy.
    def generate_proxy_response(self):
        # if AAAA record will set response code to refuse and not give an answer
        if (self.qtype == DNS.AAAA):
            answer_count, response_code = 0, 5 # TODO: this code might be wrong. validate.
        # standard query response to sinkhole
        else:
            answer_count, response_code = 1, 0

        # 1. generating dns header, appending original question and our response if applicable | append to send data
        dns_data = [create_dns_response_header(
            self.dns_id, answer_count, rd=self._rd, ad=1, cd=self._cd, rc=response_code
            ), self.question_record]
        if (answer_count):
            dns_data.append(resource_record_pack(
                49164, 1, 1, 300, 4, interface.get_ip_address(interface=self._intf).packed
            ))
        send_data = [b''.join(dns_data)]
        # 2. generating udp header, getting length from join on build data | append to send data
        udp_len = 8 + len(b''.join(send_data))
        send_data.append(udp_header_pack(
            self.dst_port, self.src_port, udp_len, 0
        ))
        # 3. generating ip header with loop to create header, calculate zerod checksum, then rebuild
        # with correct checksum | append to send data
        ip_len, checksum = 20 + udp_len, double_byte_pack(0,0)
        for i in range(2):
            ip_header = ip_header_pack(
                69, 0, ip_len, 0, 16384, 255, PROTO.UDP,
                checksum, self.dst_ip.packed, self.src_ip.packed
            )
            if i: break
            checksum = checksum_ipv4(ip_header)
        send_data.append(ip_header)
        # 4. generating ethernet header | append to send data
        send_data.append(eth_header_pack(
            self.src_mac, self.dst_mac, L2_PROTO
        ))

        # assigning joined data from above with correct byte order
        self.send_data = b''.join(reversed(send_data))

    def _enumerate_request(self, request):
        rs = request.split('.')
        r_len = len(rs)

        # tld > fqdn
        requests = ['.'.join(rs[i:]) for i in range(-2, -r_len-1, -1)]

        # adjusting for local record as needed
        if (r_len > 1):
            t_reqs = [rs[-1]]
            self.dom_local = False
        else:
            t_reqs = [None]
            self.dom_local = True

        # building bin/host id from hash for each enumerated name.
        for r in requests:
            r_hash = hash(r)
            b_id = int(f'{r_hash}'[:4])
            h_id = int(f'{r_hash}'[4:])

            t_reqs.append((b_id, h_id))

        return tuple(t_reqs)


_records = namedtuple('records', 'resource authority')


class ServerResponse:
    __slots__ = (
        '_data', '_dns_header', '_dns_query',
        '_offset',

        'dns_id', 'dns_flags', 'question_count',
        'records', 'additional_count',

        'qtype', 'qclass', 'question_record',
        'resource_record', 'data_to_cache',
        'send_data'
    )

    def __init__(self, data):
        self._data       = data
        self._dns_header = data[:12]
        self._dns_query  = data[12:]
        self._offset     = 0

        self.data_to_cache = None
        self.dns_id    = 0
        self.send_data = b''
        self.records   = _records(
            {'rcv_count': 0, 'records': []},
            {'rcv_count': 0, 'records': []}
        )

    def parse(self):
        self._header()
        self._question_record_handler()
        self._resource_record_handler()

    def _header(self):
        dns_header = dns_header_unpack(self._dns_header)
        self.dns_id           = dns_header[0]
        self.dns_flags        = dns_header[1]
        self.question_count   = dns_header[2]
        self.records.resource['rcv_count']  = dns_header[3]
        self.records.authority['rcv_count'] = dns_header[4]
        self.additional_count = dns_header[5]

    def _question_record_handler(self):
        offset = parse_query_name(self._dns_query) # www.micro.com or micro.com || sd.micro.com

        self.qtype, self.qclass = double_short_unpack(self._dns_query[offset:])
        self.question_record = self._dns_query[:offset+4] # ofsset + 4 byte info
        self.resource_record = self._dns_query[offset+4:]

    # grabbing the records contained in the packet and appending them to their designated lists to be inspected by other methods.
    # count of records is being grabbed/used from the header information
    def _resource_record_handler(self):
        # parsing standard and authority records
        a_record_count = 0
        for r_field in self.records:
            for _ in range(r_field['rcv_count']):
                record_type, record = self._parse_resource_record()
                # incrementing a record counter to limit amount of records in response
                if (record_type == DNS.A):
                    a_record_count += 1

                # filtering out a records once max count is reached
                if (a_record_count <= MAX_A_RECORD_COUNT or record_type != DNS.A):
                    r_field['records'].append(record)

    # creating byte container of dns record values to be used later. now rewriting ttl here.
    def _parse_resource_record(self):
        local_record = self.resource_record[self._offset:]

        offset = parse_query_name(local_record, self._dns_query)
        name   = local_record[:offset]
        qtype  = local_record[offset:offset+2]
        qclass = local_record[offset+2:offset+4]
        ttl    = local_record[offset+4:offset+8]
        dt_len = short_unpack(local_record[offset+8:offset+10])[0]
        data   = local_record[offset+8:offset+10+dt_len]

        self._offset += offset + dt_len + 10 # length of data + 2 bytes(length field) + 8 bytes(type, class, ttl)

        return short_unpack(qtype)[0], RESOURCE_RECORD(name, qtype, qclass, ttl, data)

    def generate_server_response(self, dns_id):
        send_data, original_ttl = [b'\x00'*14, self.question_record], 0
        for i, r_field in enumerate(self.records):
            for record in r_field['records']:
                original_ttl, modified_ttl, modified_ttl_packed = self._get_new_ttl(record.ttl)
                record.update('ttl', modified_ttl_packed)
                send_data.append(b''.join(record))

            # first enum iter filter(resource records) and ensuring its an a type, then creating cache data.
            if (not i and original_ttl):
                self.data_to_cache = CACHED_RECORD(
                    int(fast_time()) + modified_ttl,
                    modified_ttl, r_field['records']
                )

        # prepending dns header to records. this is so we have new count calculated before header creation.
        send_data[0] = self._create_header(dns_id)

        # additional records will remain intact until otherwise needed
        if (self.additional_count):
            send_data.append(self.resource_record[self._offset:])

        self.send_data = b''.join(send_data)

    def _get_new_ttl(self, record_ttl):
        '''returns dns records original ttl, the rewritten ttl, and the packed for of the rewritten ttl.'''
        record_ttl = long_unpack(record_ttl)[0]
        if (record_ttl < MINIMUM_TTL):
            new_record_ttl = MINIMUM_TTL
        # rewriting ttl to the remaining amount that was calculated from cached packet or to the maximum defined TTL
        elif (record_ttl > DEFAULT_TTL):
            new_record_ttl = DEFAULT_TTL
        # anything in between the min and max TTL will be retained
        else:
            new_record_ttl = record_ttl

        return record_ttl, new_record_ttl, long_pack(new_record_ttl)

    def _create_header(self, dns_id):
        return dns_header_pack(
            dns_id, self.dns_flags,
            self.question_count,
            len(self.records.resource['records']),
            len(self.records.authority['records']),
            self.additional_count
        )
