#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import PROTO, DNS, DNS_MASK
from dnx_gentools.def_namedtuples import QNAME_RECORD, QNAME_RECORD_UPDATE, RESOURCE_RECORD
from dnx_gentools.def_exceptions import ProtocolError

from dnx_iptools.def_structs import *
from dnx_iptools.def_structures import *
from dnx_iptools.protocol_tools import *
from dnx_iptools.cprotocol_tools import itoip, iptoi, calc_checksum
from dnx_iptools.interface_ops import load_interfaces
from dnx_iptools.packet_classes import NFPacket, RawResponse

from dns_proxy_cache import NO_QNAME_RECORD


__all__ = (
    'ClientQuery', 'DNSPacket', 'ProxyResponse',

    'ttl_rewrite'
)


class ClientQuery:
    qtype:  int
    qclass: int
    qname:  str

    request_identifier: tuple[int, int, int]

    question_record: memoryview
    additional_records: memoryview

    __slots__ = (
        '_dns_header', '_dns_query',

        'client_ip', 'client_port',
        'local_domain', 'top_domain',
        'keepalive', 'fallback',
        'send_data', 'sendto',

        'qr', 'op', 'aa', 'tc', 'rd',
        'ra', 'zz', 'ad', 'cd', 'rc',

        'dns_id',
        'request_identifier', 'requests',
        'qtype', 'qclass', 'qname',
        'question_record', 'additional_records'
    )

    def __init__(self, address: Address, sock_info):

        self.client_ip:   int = iptoi(address[0])
        self.client_port: int = address[1]

        if (sock_info):
            self.sendto = sock_info.sendto  # 5 object namedtuple

        self.local_domain: bool = False
        self.top_domain:   bool = address is NULL_ADDR
        self.keepalive: bool = False
        self.fallback:  bool = False

        self.dns_id: int = 1
        # self.qname:  str = ''

        # OPT record defaults #
        # TODO: add better support for this
        self.additional_records: bytes = b''

    def __str__(self):
        return f'dns_query(host={self.client_ip}, port={self.client_port}, domain={self.qname})'

    # TODO: see if we should validate whether there is an indicated question record before continuing
    # TODO: implement DNS label/name validity checks and drop packet if fail. do same on response
    def parse(self, data: memoryview) -> None:

        _dns_header, dns_query = data[:12], data[12:]

        dns_header: tuple[int, ...] = dns_header_unpack(_dns_header)
        self.dns_id: int = dns_header[0]

        self.qr: int = dns_header[1] & DNS_MASK.QR
        self.op: int = dns_header[1] & DNS_MASK.OP
        self.aa: int = dns_header[1] & DNS_MASK.AA
        self.tc: int = dns_header[1] & DNS_MASK.TC
        self.rd: int = dns_header[1] & DNS_MASK.RD
        self.ra: int = dns_header[1] & DNS_MASK.RA
        self.zz: int = dns_header[1] & DNS_MASK.ZZ
        self.ad: int = dns_header[1] & DNS_MASK.AD
        self.cd: int = dns_header[1] & DNS_MASK.CD
        self.rc: int = dns_header[1] & DNS_MASK.RC

        # www.micro.com or micro.com || sd.micro.com
        offset, self.qname, self.local_domain = parse_query_name(dns_query)

        self.qtype, self.qclass = double_short_unpack(dns_query[offset:])
        self.question_record    = dns_query[:offset + 4]
        self.additional_records = dns_query[offset + 4:]

        self.request_identifier = (self.client_ip, self.client_port, dns_header[0])  # dns_id

    def generate_record_response(self, record_ip: int = 0, configured_ttl: int = THIRTY_MIN) -> bytearray:
        '''builds a dns query response for locally configured records.

        if host_ip is not passed in, the resource record section of the payload will not be generated.
        '''
        flags = 32896 | self.rd | self.ad | self.cd | self.rc

        send_data = bytearray(dns_header_pack(self.dns_id, flags, 1, 1, 0, 0))
        send_data += self.question_record

        if (record_ip):
            send_data += resource_record_pack(49164, 1, 1, configured_ttl, 4, record_ip)

        return send_data

    def generate_cached_response(self, cached_dom: QNAME_RECORD_UPDATE) -> bytearray:

        send_data = bytearray(
            dns_header_pack(self.dns_id, 32896 | self.rd | self.cd, 1, len(cached_dom.records), 0, 0)
        )
        send_data += self.question_record

        for record in cached_dom.records:
            record.ttl = long_pack(cached_dom.ttl)
            send_data += byte_join(record)

        return send_data

    def generate_dns_query(self, dns_id: int, protocol: PROTO) -> bytearray:
        # setting additional data flag in dns header if detected
        arc = 1 if self.additional_records else 0

        # initializing byte array with (2) bytes. these get overwritten with query len actual after processing
        send_data = bytearray(2)

        send_data += dns_header_pack(dns_id, self.rd | self.ad | self.cd, 1, 0, 0, arc)
        send_data += domain_stob(self.qname)
        send_data += double_short_pack(self.qtype, 1)
        send_data += self.additional_records

        # ternary looked gross so using standard if statement
        if (protocol is PROTO.DNS_TLS):
            send_data[:2] = short_pack(len(send_data)-2)
        else:
            send_data = send_data[2:]

        return send_data

    @classmethod
    def init_local_query(cls, qname: str, keepalive: bool = False) -> Union[bytearray, ClientQuery]:
        '''alternate constructor for creating locally generated queries (top domain or keepalive requests).

        if keepalive is set, a bytearray of send data is returned.
        If not keepalive, an instance of ClientQuery will be returned, which requires subsequent call to a send_data
        generation method.
        '''
        self = cls(NULL_ADDR, None)
        # hardcoded qtype can change if needed.
        self.qname = qname
        self.qtype = 1

        self.rd = DNS_MASK.RD
        self.ad = DNS_MASK.AD
        self.cd = DNS_MASK.CD

        # keepalive are TLS only so we can hardcode the protocol.
        if (keepalive):
            return self.generate_dns_query(DNS.KEEPALIVE, PROTO.DNS_TLS)

        return self


# ======================================
# PROXY - FULL INSPECTION, DIRECT SOCKET
# ======================================
ip_hdr_template: Structure = PR_IP_HDR(
    (('ver_ihl', 69), ('tos', 0), ('ident', 0), ('flags_fro', 16384), ('ttl', 255), ('protocol', PROTO.UDP))
)
udp_hdr_template: Structure = PR_UDP_HDR(
    (('checksum', 0),)
)
std_rr_template: Structure = DNS_STD_RR(
    (('ptr', 49164), ('type', 1), ('class', 1), ('ttl', 300), ('rd_len', 4))
)


class DNSPacket(NFPacket):
    qtype:  int
    qclass: int
    qname:  str

    __slots__ = (
        'action',

        '_dns_header', '_dns_query',

        'dns_id', 'local_domain',

        'qname', 'requests', 'tld', 'request_identifier',
        'qtype', 'qclass', 'question_record',

        'qr', 'rd', 'ad', 'cd',
    )

    def _before_exit(self, mark: int):

        # ============================
        # DNS HEADER (12 bytes)
        # ============================
        dns_header: StructUnpack = dns_header_unpack(self.udp_payload[:12])

        # filtering out non query flags (malformed payload)
        self.qr = dns_header[1] & DNS_MASK.QR
        if (self.qr != DNS.QUERY):
            raise ProtocolError

        # finishing parse of dns header post filter
        self.dns_id = dns_header[0]
        self.rd = dns_header[1] & DNS_MASK.RD
        self.ad = dns_header[1] & DNS_MASK.AD
        self.cd = dns_header[1] & DNS_MASK.CD

        # ============================
        # QUESTION RECORD (index 12+)
        # ============================
        dns_query: bytearray = self.udp_payload[12:]  # 13+ is query data

        # parsing dns name queried and byte offset due to variable length | ex www.micro.com or micro.com
        offset: int
        query_info: tuple[str, bool]
        offset, self.qname, self.local_domain = parse_query_name(dns_query)

        # defining question record
        self.question_record: bytearray = dns_query[:offset + 4]

        # defining questions record fields
        self.qtype, self.qclass = double_short_unpack(dns_query[offset:])

        # hashing queried name enumerating any subdomains (signature matching)
        # defining unique tuple for informing dns server of inspection results
        self.requests, self.tld = _enumerate_request(self.qname, self.local_domain)
        self.request_identifier = (self.src_ip, self.src_port, self.dns_id)

def _enumerate_request(request: str, local_domain: bool) -> tuple[list[int], str]:
    rs: list[str] = request.split('.')

    # tld > fqdn
    requests: list[int] = [
        hash(dot_join(rs[i:])) & UINT32_MAX for i in range(-2, -len(rs)-1, -1)
    ]

    # adjusting for local record as needed
    tld: str = '' if local_domain else rs[-1]

    return requests, tld


# ================
# SERVER RESPONSE
# ================
_MINIMUM_TTL: bytes = long_pack(MINIMUM_TTL)
_DEFAULT_TTL: bytes = long_pack(DEFAULT_TTL)

def ttl_rewrite(data: bytes, dns_id: int, len=len, min=min, max=max) -> tuple[bytearray, QNAME_RECORD]:

    mem_data = memoryview(data)
    dns_header:  memoryview = mem_data[:12]
    dns_payload: memoryview = mem_data[12:]

    # converting external/unique dns id back to the original dns id of the client
    send_data = bytearray(short_pack(dns_id))

    # ================
    # HEADER
    # ================
    _dns_header: tuple = dns_header_unpack(dns_header)

    resource_count:  int = _dns_header[3]
    authority_count: int = _dns_header[4]
    # additional_count = _dns_header[5]

    send_data += dns_header[2:]

    # ================
    # QUESTION RECORD
    # ================
    # www.micro.com or micro.com || sd.micro.com
    offset: int = parse_query_name(dns_payload, quick=True) + 4

    send_data += dns_payload[:offset]

    # ================
    # RESOURCE RECORD
    # ================
    # resource_records = dns_payload[offset + 4:]

    original_ttl = 0
    record_cache = []

    # parsing standard and authority records
    for record_count in [resource_count, authority_count]:

        # iterating once for every record based on provided record count. if this number is forged/tampered with it
        # will cause the parsing to fail. NOTE: ensure this isn't fatal.
        for _ in range(record_count):
            record_type, record, offset = _parse_record(dns_payload, offset)

            # TTL rewrite done on A/CNAME records which functionally clamp TTLs between a min and max value.
            # CNAME ttl can differ, but will get clamped with A so wil; likely end up the same as A records.
            # NOTE: only caching A/CNAME records
            if (record_type in [DNS.A, DNS.CNAME]):
                original_ttl = long_unpack(record.ttl)[0]
                record.ttl = long_pack(
                    max(MINIMUM_TTL, min(original_ttl, DEFAULT_TTL))
                )

                send_data += record

                # limits A record caching, so we aren't caching excessive amount of records with the same qname
                if (len(record_cache) < MAX_A_RECORD_COUNT or record_type != DNS.A):
                    record_cache.append(record)

            # dns system level, ns, mx, and txt records don't need to be clamped and will be relayed as is
            else:
                send_data += record

    # keeping any additional records intact
    # TODO: see if modifying/ manipulating additional records would be beneficial or even useful in any way
    send_data += dns_payload[offset:]

    if (record_cache):
        return send_data, QNAME_RECORD(fast_time() + original_ttl, original_ttl, record_cache)

    return send_data, NO_QNAME_RECORD

def _parse_record(dns_payload: memoryview, cur_offset: int) -> tuple[int, RESOURCE_RECORD, int]:
    new_offset: int = parse_query_name(dns_payload, cur_offset, quick=True)

    record_name = bytes(dns_payload[cur_offset:new_offset])
    record_values = bytes(dns_payload[new_offset:])
    # resource record data len, usually 4 for ip address, but can vary.
    # calculating first, so we can single shot creation of the byte container.
    dt_len = btoia(record_values[8:10])

    resource_record =  RESOURCE_RECORD(
        record_name,
        record_values[:2],
        record_values[2:4],
        record_values[4:8],
        record_values[8:10 + dt_len]
    )

    # name len + 8 bytes(type, class, ttl) + 2 bytes(length field) + data len
    new_offset += 10 + dt_len

    return btoia(resource_record.qtype), resource_record, new_offset

# ===============
# PROXY RESPONSE
# ===============
class ProxyResponse(RawResponse):
    _intfs = load_interfaces(exclude=['wan'])

    @staticmethod
    def _prepare_packet(packet: ProxyPackets, dnx_src_ip: int) -> bytearray:
        # DNS HEADER + PAYLOAD
        # AAAA record set r code to "domain name does not exist" without record response ac=0, rc=3
        udp_payload = bytearray()
        if (packet.qtype == DNS.AAAA):
            udp_payload += dns_header_pack(packet.dns_id, 32899 | packet.rd | packet.ad | packet.cd, 1, 0, 0, 0)
            udp_payload += packet.question_record

        # standard query response to sinkhole. default answer count and response code
        else:
            resource_record = std_rr_template()

            resource_record.rd_data = dnx_src_ip

            udp_payload += dns_header_pack(packet.dns_id, 32896 | packet.rd | packet.ad | packet.cd, 1, 1, 0, 0)
            udp_payload += packet.question_record
            udp_payload += resource_record.assemble()

        # UDP HEADER
        udphdr = udp_hdr_template()

        udphdr.src_port = packet.dst_port
        udphdr.dst_port = packet.src_port
        udphdr.len = 8 + len(udp_payload)

        udp_header: bytearray = udphdr.assemble()

        # IP HEADER
        iphdr = ip_hdr_template()

        iphdr.tl = 28 + len(udp_payload)
        iphdr.src_ip = dnx_src_ip
        iphdr.dst_ip = packet.src_ip

        ip_header: bytearray = iphdr.assemble()
        ip_header[10:12] = calc_checksum(ip_header)

        return ip_header + udp_header + udp_payload
