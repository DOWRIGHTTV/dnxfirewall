#!/usr/bin/env python3

import os, sys

from socket import inet_aton
from collections import namedtuple

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-2]))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.def_structs import * # pylint: disable=unused-wildcard-import
from dnx_iptools.protocol_tools import * # pylint: disable=unused-wildcard-import
from dnx_gentools.standard_tools import bytecontainer
from dnx_sysmods.configure.def_namedtuples import CACHED_RECORD

from dnx_iptools.packet_classes import RawPacket


class ClientRequest:
    __slots__ = (
        '_data', '_dns_header', '_dns_query', '_arc',

        # init
        'address', 'sendto', 'top_domain',
        'keepalive', 'dom_local', 'fallback',
        'dns_id', 'request', 'send_data',
        'additional_data',

        # dns
        'qr', 'op', 'aa', 'tc', 'rd',
        'ra', 'zz', 'ad', 'cd', 'rc',

        'request_identifier', 'requests', 'qtype',
        'qclass', 'question_record'
    )

    def __init__(self, data, address, sock_info):
        self._data   = data
        self.address = address
        if (data):
            self._dns_header = data[:12]
            self._dns_query  = data[12:]

        if (sock_info):
            self.sendto = sock_info.sendto # 5 object named tuple

        self.top_domain = False if address[0] else True
        self.dom_local  = False
        self.keepalive  = False
        self.fallback   = False

        self.dns_id    = 1
        self.request   = None
        self.send_data = b''

        # OPT record defaults # TODO: add better support for this
        self._arc = 0
        self.additional_data = b''

    def __str__(self):
        return f'dns_query(host={self.address[0]}, port={self.address[1]}, request={self.request})'

    def parse(self):
        if (not self._data):
            raise TypeError(f'{__class__.__name__} cannot parse data set to None.')

        self._parse_header(self._dns_header)
        self._parse_dns_query(self._dns_query)

        self.request_identifier = (*self.address, self.dns_id)

    # TODO: see if we should validate whether there is an indicated question record before continuing
    def _parse_header(self, dns_header):
        dns_header = dns_header_unpack(dns_header)
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

    def _parse_dns_query(self, dns_query):
        self.request, offset = parse_query_name(dns_query, qname=True) # www.micro.com or micro.com || sd.micro.com
        # will prevent local records from getting external resolved
        if ('.' not in self.request):
            self.dom_local = True

        self.qtype, self.qclass = double_short_unpack(dns_query[offset:])
        self.question_record = dns_query[:offset+4] # ofsset + 4 byte info
        self.additional_data = dns_query[offset+4:]

    def generate_record_response(self, host_ip=None, configured_ttl=THIRTY_MIN):
        '''builds a dns server response for locally configured records. if no record is found, an empty
        response (no resource record) will be generated.'''
        if (self.send_data):
            raise RuntimeWarning('send data has already been created for this query.')

        send_data = [
            create_dns_response_header(self.dns_id, rd=self.rd, cd=self.cd),
            self.question_record
        ]

        if (host_ip):
            send_data.append(resource_record_pack(
                49164, 1, 1, configured_ttl, 4, inet_aton(host_ip)
            ))

        self.send_data = byte_join(send_data)

    def generate_cached_response(self, cached_dom):
        if (self.send_data):
            raise RuntimeWarning('send data has already been created for this query.')

        send_data = [create_dns_response_header(
            self.dns_id, len(cached_dom.records), rd=self.rd, cd=self.cd
        )]
        send_data.append(self.question_record)
        for record in cached_dom.records:
            record.update('ttl', long_pack(cached_dom.ttl))
            send_data.append(byte_join(record))

        self.send_data = byte_join(send_data)

    def generate_dns_query(self, dns_id, protocol):
        if (self.send_data):
            raise RuntimeWarning('send data has already been created for this query.')

        # if additional data seen after question record, will mark additional record count as 1 in dns header
        if (self.additional_data):
            self._arc = 1

        # TODO: see what the list bounds are for having to resize. if the header + length fits, we can remove
        # the pre assignment length bytes. make sure insert scenario is looked at.
        send_data = [b'\x00\x00', create_dns_query_header(dns_id, self._arc, cd=self.cd)]
        send_data.append(convert_dns_string_to_bytes(self.request))
        send_data.append(double_short_pack(self.qtype, 1))
        send_data.append(self.additional_data)

        if (protocol is PROTO.DNS_TLS):
            send_data[0] = short_pack(len(byte_join(send_data[1:])))
        else:
            send_data.pop(0)

        self.send_data = byte_join(send_data)

    @classmethod
    def generate_local_query(cls, request, cd=1):
        '''alternate constructor for creating locally generated queries (top domains).'''

        self = cls(None, NULL_ADDR, None)
        # harcorded qtype can change if needed.
        self.request = request
        self.qtype   = 1
        self.cd      = cd

        return self

    @classmethod
    def generate_keepalive(cls, request, protocol, cd=1):
        '''alternate constructor for creating locally generated keep alive queries.'''

        self = cls(None, NULL_ADDR, None)

        # harcorded qtype can change if needed.
        self.request = request
        self.qtype   = 1
        self.cd      = cd

        self.generate_dns_query(DNS.KEEPALIVE, protocol)

        return self


class ProxyRequest(RawPacket):

    __slots__ = (
        '_dns_header', '_dns_query',

        'request', 'requests', 'request_identifier',
        'dom_local', 'qtype', 'qclass', 'dns_id', 'question_record',

        'qr', '_rd', '_cd', 'send_data',
    )

    def __init__(self):
        super().__init__()

        self.qr     = None
        self.qtype  = None
        self.qclass = None
        self.request_identifier = None

    @property
    def continue_condition(self):
        return True if self.protocol is PROTO.UDP else False

    # extension from parent class.
    def _before_exit(self):
        if (self.dst_port == PROTO.DNS):
            self._header(self.udp_payload[:12]) # first 12 bytes are header

            if (self.qr == DNS.QUERY):
                self._query(self.udp_payload[12:]) # 13+ is query data

                self.request_identifier = (f'{self.src_ip}', self.src_port, self.dns_id)

    # dns header
    def _header(self, dns_header):
        dns_header = dns_header_unpack(dns_header)
        self.dns_id = dns_header[0]
        self.qr  = dns_header[1] >> 15 & 1
        self._rd = dns_header[1] >> 8  & 1
        self._cd = dns_header[1] >> 4  & 1

    # dns query
    def _query(self, dns_query):
        request, offset = parse_query_name(dns_query, qname=True) # www.micro.com or micro.com || sd.micro.com
        self.request  = request
        self.requests = self._enumerate_request(request)

        self.qtype, self.qclass = double_short_unpack(dns_query[offset:])
        self.question_record = dns_query[:offset+4] # ofsset + 4 byte info

    # will create send data object for used by proxy.
    def generate_proxy_response(self):
        # if AAAA record, set response code to "domain name does not exist" without record response
        if (self.qtype == DNS.AAAA):
            answer_count, response_code = 0, 3

        # standard query response to sinkhole
        else:
            answer_count, response_code = 1, 0

        # 1. generating dns header, appending original question and our response if applicable | append to send data
        dns_data = [create_dns_response_header(
            self.dns_id, answer_count, rd=self._rd, ad=1, cd=self._cd, rc=response_code
            ), self.question_record]

        if (answer_count):
            dns_data.append(resource_record_pack(
                49164, 1, 1, 300, 4, self.intf_ip
            ))

        send_data = [byte_join(dns_data)]

        # 2. generating udp header, getting length from join on build data | append to send data
        udp_len = 8 + len(byte_join(send_data))
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

        #NOTE: we shouldnt have to track ethernet headers anymore
        # # 4. generating ethernet header | append to send data
        # send_data.append(eth_header_pack(
        #     self.src_mac, self.dst_mac, L2_PROTO
        # ))

        # assigning joined data from above with correct byte order
        self.send_data = byte_join(reversed(send_data))

    def _enumerate_request(self, request):
        rs = request.split('.')
        r_len = len(rs)

        # tld > fqdn
        requests = tuple('.'.join(rs[i:]) for i in range(-2, -r_len-1, -1))

        # adjusting for local record as needed
        if (r_len > 1):
            t_reqs = [rs[-1]]
            self.dom_local = False

        else:
            t_reqs = [None]
            self.dom_local = True

        fast_int = int
        # building bin/host id from hash for each enumerated name.
        for r in requests:
            r_hash = hash(r)
            b_id = fast_int(f'{r_hash}'[:4])
            h_id = fast_int(f'{r_hash}'[4:])

            t_reqs.append((b_id, h_id))

        return tuple(t_reqs)


_records = namedtuple('records', 'resource authority')
_RESOURCE_RECORD = bytecontainer('resource_record', 'name qtype qclass ttl data')


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
        self.dns_id         = dns_header[0]
        self.dns_flags      = dns_header[1]
        self.question_count = dns_header[2]
        self.records.resource['rcv_count']  = dns_header[3]
        self.records.authority['rcv_count'] = dns_header[4]
        self.additional_count = dns_header[5]

    def _question_record_handler(self):
        dns_query = self._dns_query

        offset = parse_query_name(dns_query) # www.micro.com or micro.com || sd.micro.com

        self.qtype, self.qclass = double_short_unpack(dns_query[offset:])
        self.question_record = dns_query[:offset+4] # ofsset + 4 byte info
        self.resource_record = dns_query[offset+4:]

    # grabbing the records contained in the packet and appending them to their designated lists to be inspected by other methods.
    # count of records is being grabbed/used from the header information
    def _resource_record_handler(self):
        a_record_count, offset = 0, 0

        # parsing standard and authority records
        for r_field in self.records:

            # iterating once for every record based on count sent. if this number is forged/tampered with
            # it will cause the parsing to fail. NOTE: ensure this isnt fatal
            for _ in range(r_field['rcv_count']):
                record_type, record, offset = self._parse_resource_record(offset)

                # incrementing a record counter to limit amount of records in response
                if (record_type == DNS.A):
                    a_record_count += 1

                # filtering out a records once max count is reached
                if (a_record_count <= MAX_A_RECORD_COUNT or record_type != DNS.A):
                    r_field['records'].append(record)

        # instance assignment to be used by response generation method
        self._offset = offset

    # creating byte container of dns record values to be used later. now rewriting ttl here.
    def _parse_resource_record(self, total_offset):
        local_record = self.resource_record[total_offset:]

        offset = parse_query_name(local_record, self._dns_query)
        name   = local_record[:offset]
        qtype  = local_record[offset:offset+2]
        qclass = local_record[offset+2:offset+4]
        ttl    = local_record[offset+4:offset+8]
        dt_len = short_unpack(local_record[offset+8:offset+10])[0]
        data   = local_record[offset+8:offset+10+dt_len]

        total_offset += offset + dt_len + 10 # length of data + 2 bytes(length field) + 8 bytes(type, class, ttl)

        return short_unpack(qtype)[0], _RESOURCE_RECORD(name, qtype, qclass, ttl, data), total_offset

    def generate_server_response(self, dns_id):
        send_data, original_ttl = [b'\x00'*14, self.question_record], 0

        # parsing standard and authority records
        for i, r_field in enumerate(self.records):

            # ttl rewrite to configured bounds (clamping)
            for record in r_field['records']:
                original_ttl, modified_ttl, modified_ttl_packed = self._get_new_ttl(record.ttl)
                record.update('ttl', modified_ttl_packed)
                send_data.append(byte_join(record))

            # first enumerate iteration filter(resource records) and ensuring its an "A" record, then creating cache data.
            # NOTE: system will cache for full ttl. the server will override to configured amount responding sending to client.
            if (not i and original_ttl):
                self.data_to_cache = CACHED_RECORD(
                    int(fast_time()) + original_ttl,
                    original_ttl, r_field['records']
                )

        # replacing dns head placeholder. needed new record counts calculated before header creation.
        send_data[0] = self._create_header(dns_id)

        # additional records will remain intact until otherwise needed
        if (self.additional_count):
            send_data.append(self.resource_record[self._offset:])

        self.send_data = byte_join(send_data)

    def _get_new_ttl(self, record_ttl):
        '''returns dns records original ttl, the rewritten ttl, and the packed form of the rewritten ttl.'''
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
