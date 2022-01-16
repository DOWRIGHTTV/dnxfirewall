#!/usr/bin/env python3

from socket import inet_aton
from collections import namedtuple

from dnx_gentools.def_constants import *
from dnx_gentools.standard_tools import bytecontainer
from dnx_gentools.def_namedtuples import CACHED_RECORD

from dnx_iptools.def_structs import *
from dnx_iptools.protocol_tools import *
from dnx_iptools.def_structures import *
from dnx_iptools.packet_classes import RawPacket


class ClientRequest:
    __slots__ = (
        '_data', '_dns_header', '_dns_query',

        # init
        'address', 'sendto', 'top_domain',
        'keepalive', 'local_domain', 'fallback',
        'dns_id', 'request', 'send_data',
        'additional_records',

        # dns
        'qr', 'op', 'aa', 'tc', 'rd',
        'ra', 'zz', 'ad', 'cd', 'rc',

        'request_identifier', 'requests', 'qtype',
        'qclass', 'question_record'
    )

    def __init__(self, address, sock_info):
        self.address = address
        if (sock_info):
            self.sendto = sock_info.sendto  # 5 object namedtuple

        self.local_domain = False
        self.top_domain = False if address[0] else True
        self.keepalive  = False
        self.fallback   = False

        self.dns_id    = 1
        self.request   = None
        self.send_data = b''

        # OPT record defaults # TODO: add better support for this
        self.additional_records = b''

    def __str__(self):
        return f'dns_query(host={self.address[0]}, port={self.address[1]}, request={self.request})'

    # TODO: see if we should validate whether there is an indicated question record before continuing
    # TODO: implement DNS label/name validity checks and drop packet if fail. do same on response
    def parse(self, data):

        _dns_header, dns_query = data[:12], data[12:]

        dns_header = dns_header_unpack(_dns_header)
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

        # www.micro.com or micro.com || sd.micro.com
        offset, query_info = parse_query_name(dns_query, qname=True)
        self.request, self.local_domain = query_info

        self.qtype, self.qclass = double_short_unpack(dns_query[offset:])
        self.question_record    = dns_query[:offset + 4]
        self.additional_records = dns_query[offset + 4:]

        self.request_identifier = (*self.address, dns_header[0])  # dns_id

    def generate_record_response(self, host_ip=None, configured_ttl=THIRTY_MIN):
        '''builds a dns query response for locally configured records. if host_ip is not passed in, the resource record
        section of the payload will not be generated.'''

        send_data = bytearray(
            create_dns_response_header(self.dns_id, rd=self.rd, cd=self.cd)
        )
        send_data += self.question_record

        if (host_ip):
            send_data += resource_record_pack(49164, 1, 1, configured_ttl, 4, inet_aton(host_ip))

        return send_data

    def generate_cached_response(self, cached_dom):
        send_data = bytearray(
            create_dns_response_header(self.dns_id, len(cached_dom.records), rd=self.rd, cd=self.cd)
        )
        send_data += self.question_record

        for record in cached_dom.records:
            record.ttl = long_pack(cached_dom.ttl)
            send_data += byte_join(record)

        return send_data

    def generate_dns_query(self, dns_id, protocol):
        # setting additional data flag in dns header if detected
        arc = 1 if self.additional_records else 0

        # initializing byte array with (2) bytes. these get overwritten with query len actual after processing
        send_data = bytearray(2)

        send_data += create_dns_query_header(dns_id, arc, cd=self.cd)
        send_data += domain_stob(self.request)
        send_data += double_short_pack(self.qtype, 1)
        send_data += self.additional_records

        # ternary looked gross so using standard if statement
        if (protocol is PROTO.DNS_TLS):
            send_data[:2] = short_pack(len(send_data)-2)
        else:
            send_data = send_data[2:]

        self.send_data = send_data

    @classmethod
    def generate_local_query(cls, request, cd=1):
        '''alternate constructor for creating locally generated queries (top domains).'''

        self = cls(NULL_ADDR, None)
        # hardcoded qtype can change if needed.
        self.request = request
        self.qtype   = 1
        self.cd      = cd

        return self

    @classmethod
    def generate_keepalive(cls, request, protocol, cd=1):
        '''alternate constructor for creating locally generated keep alive queries.'''

        self = cls(NULL_ADDR, None)

        # hardcoded qtype can change if needed.
        self.request = request
        self.qtype   = 1
        self.cd      = cd

        self.generate_dns_query(DNS.KEEPALIVE, protocol)

        return self


# ======================================
# PROXY - FULL INSPECTION, DIRECT SOCKET
# ======================================
ip_header_template = PR_IP_HDR(
    **{'ver_ihl': 69, 'tos': 0, 'ident': 0, 'flags_fro': 16384, 'ttl': 255, 'protocol': PROTO.UDP}
)
udp_header_template = PR_UDP_HDR(**{'checksum': 0})

std_resource_record_template = DNS_STD_RR(**{'ptr': 49164, 'type': 1, 'class': 1, 'ttl': 300, 'rd_len': 4})


class ProxyRequest(RawPacket):

    __slots__ = (
        '_dns_header', '_dns_query',

        'request', 'requests', 'request_identifier',
        'local_domain', 'qtype', 'qclass', 'dns_id', 'question_record',

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

    def _before_exit(self):
        # filtering down to dns protocol
        if (self.dst_port != PROTO.DNS):
            return

        # ===========================
        # DNS HEADER (12 bytes)
        # ===========================
        dns_header = dns_header_unpack(self.udp_payload[:12])

        # filtering out non query flags. this would also imply malformed payload.
        self.qr = dns_header[1] >> 15 & 1
        if (self.qr != DNS.QUERY):
            return

        # finishing parse of dns header post filter
        self.dns_id = dns_header[0]
        self._rd = dns_header[1] >> 8 & 1
        self._cd = dns_header[1] >> 4 & 1

        # ===========================
        # QUESTION RECORD (index 12+)
        # ===========================
        dns_query = self.udp_payload[12:self.udp_len]  # 13+ is query data

        # parsing dns name queried and byte offset due to variable length | ex www.micro.com or micro.com
        offset, query_info = parse_query_name(dns_query, qname=True)

        # defining question record
        self.question_record = dns_query[:offset + 4]

        # defining questions record fields
        self.request, self.local_domain = query_info
        self.qtype, self.qclass = double_short_unpack(dns_query[offset:])

        # hashing queried name enumerating any subdomains (signature matching)
        # defining unique tuple for informing dns server of inspection results
        self.requests = _enumerate_request(*query_info)
        self.request_identifier = (int_to_ipaddr(self.src_ip), self.src_port, self.dns_id)

    # will create send data object for used by proxy.
    def generate_proxy_response(self, len=len):
        # DNS HEADER + PAYLOAD
        # AAAA record set r code to "domain name does not exist" without record response ac=0, rc=3
        udp_payload = bytearray()
        if (self.qtype == DNS.AAAA):
            udp_payload += create_dns_response_header(self.dns_id, 0, rd=self._rd, ad=1, cd=self._cd, rc=3)
            udp_payload += self.question_record

        # standard query response to sinkhole. default answer count and response code
        else:
            resource_record = std_resource_record_template()

            resource_record.rd_data = btoia(self.intf_ip)

            udp_payload += create_dns_response_header(self.dns_id, rd=self._rd, ad=1, cd=self._cd)
            udp_payload += self.question_record
            udp_payload += resource_record.assemble()

        # UDP HEADER
        udp_header = udp_header_template()

        udp_header.src_port = self.dst_port
        udp_header.dst_port = self.src_port
        udp_header.len = 8 + len(udp_payload)

        # IP HEADER
        ip_header = ip_header_template()

        ip_header.tl = 28 + len(udp_payload)
        ip_header.src_ip = self.dst_ip
        ip_header.dst_ip = self.src_ip

        ip_header.checksum = checksum_ipv4(ip_header.assemble())

        self.send_data = ip_header.assemble() + udp_header.assemble() + udp_payload


def _enumerate_request(request, local_domain, len=len, int=int, hash=hash):
    rs = request.split('.')

    # tld > fqdn
    requests = [dot_join(rs[i:]) for i in range(-2, -len(rs)-1, -1)]

    # adjusting for local record as needed
    req_ids = [rs[-1]] if local_domain else [None]

    # building bin/host id from hash for each enumerated name.
    for r in requests:
        r_hash = hash(r)
        b_id = int(f'{r_hash}'[:4])
        h_id = int(f'{r_hash}'[4:])

        req_ids.append((b_id, h_id))

    return req_ids


# ================
# SERVER RESPONSE
# ================
_records_container = namedtuple('record_container', 'counts records')
_resource_records = namedtuple('resource_records', 'resource authority')
_RESOURCE_RECORD = bytecontainer('resource_record', 'name qtype qclass ttl data')

_MINIMUM_TTL = long_pack(MINIMUM_TTL)
_DEFAULT_TTL = long_pack(DEFAULT_TTL)

def ttl_rewrite(data, dns_id, len=len, min=min, max=max):
    dns_header, dns_payload = data[:12], data[12:]

    # converting external/unique dns id back to original dns id of client
    send_data = bytearray(short_pack(dns_id))

    # ================
    # HEADER
    # ================
    _dns_header = dns_header_unpack(dns_header)

    resource_count = _dns_header[3]
    authority_count = _dns_header[4]
    # additional_count = _dns_header[5]

    send_data += dns_header[2:]

    # ================
    # QUESTION RECORD
    # ================
    # www.micro.com or micro.com || sd.micro.com
    offset = parse_query_name(dns_payload)

    send_data += dns_payload[:offset + 4]

    # ================
    # RESOURCE RECORD
    # ================
    # resource_records = dns_payload[offset + 4:]

    original_ttl, record_cache = 0, []

    # parsing standard and authority records
    for record_count in [resource_count, authority_count]:

        # iterating once for every record based on provided record count. if this number is forged/tampered with it
        # will cause the parsing to fail. NOTE: ensure this isn't fatal.
        for _ in range(record_count):
            record_type, record, offset = _parse_record(dns_payload, offset)

            # TTL rewrite done on A records which functionally clamps TTLs between a min and max value. CNAME is listed
            # first, followed by A records so the original_ttl var will be whatever the last A record ttl parsed is.
            # generally all A records have the same ttl. CNAME ttl can differ, but will get clamped with A so will
            # likely end up the same as A records.
            if (record_type in [DNS.A, DNS.CNAME]):
                original_ttl = long_unpack(record.ttl)[0]
                record.ttl = long_pack(
                    max(MINIMUM_TTL, min(original_ttl, DEFAULT_TTL))
                )

                send_data += record

                # limits A record caching, so we aren't caching excessive amount of records with the same qname
                if (len(record_cache) < MAX_A_RECORD_COUNT or record_type != DNS.A):
                    record_cache.append(record)

            # dns system level, mail, and txt records don't need to be clamped and will be relayed to client as is
            else:
                send_data += record

    # keeping any additional records intact
    # TODO: see if modifying/ manipulating additional records would be beneficial or even useful in any way
    send_data += dns_payload[offset:]

    if (record_cache):
        return send_data, CACHED_RECORD(int(fast_time()) + original_ttl, original_ttl, record_cache)

    return send_data, None

def _parse_record(dns_payload, cur_offset):
    new_offset = cur_offset + parse_query_name(dns_payload, cur_offset)

    # slicing out current ptr index for faster reference
    record_name = dns_payload[cur_offset: new_offset]
    record_values = dns_payload[new_offset:]

    # resource record data len. generally 4 for ip address, but can vary. calculating first so we can single shot
    # create byte container below.
    dt_len = btoia(record_values[8:10])

    resource_record = _RESOURCE_RECORD(
        record_name,
        record_values[:2],
        record_values[2:4],
        record_values[4:8],
        record_values[8:10 + dt_len]
    )

    # name len + 2 bytes(length field) + 8 bytes(type, class, ttl) + data len
    new_offset += 10 + dt_len

    return btoia(resource_record.qtype), resource_record, new_offset
