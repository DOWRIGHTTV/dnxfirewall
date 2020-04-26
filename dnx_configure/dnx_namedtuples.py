#!/usr/bin/env python3

from collections import namedtuple as _namedtuple
from dnx_iptools.dnx_standard_tools import ByteContainer as _ByteContainer

# NAMED TUPLES
#--------------
#DHCP SERVER
DHCP_REQUEST_INFO  = _namedtuple('dhcp_request_info' ,'message_type, xID, server_identifier, mac_address, client_address, requested_ip')
DHCP_RESPONSE_INFO = _namedtuple('dhcp_response_info', 'xID mac_address ciaddr handout_ip options')

#DNS PROXY
DNS_SERVERS = _namedtuple('dns_servers', 'primary secondary')
PROXY_DECISION = _namedtuple('proxy_decision', 'name decision')
RELAY_CONN = _namedtuple('relay_conn', 'remote_ip sock')
DNS_CACHE  = _namedtuple('dns_cache', 'ttl records')
CACHED_RECORD = _namedtuple('cached_record', 'expire ttl records')
DNS_REQUEST_INFO = _namedtuple('request_info', 'client_address request, request2')
DNS_REQUEST_RESULTS = _namedtuple('request_results', 'redirect, reason, category')
DNS_LOG = _namedtuple('dns_log', 'src_ip request category reason action')
BLOCKED_LOG = _namedtuple('blocked_log', 'src_ip request category reason action')

SIGNATURES = _namedtuple('signatures', 'en_dns dns tld keyword')
WHITELIST  = _namedtuple('whitelist', 'dns ip')
BLACKLIST  = _namedtuple('blacklist', 'dns')

# IPS
IPS_WAN_INFO = _namedtuple('ips_wan_info', 'interface ip mac')
IPS_IP_INFO  = _namedtuple('ips_ip_info', 'tracked_ip tracked_port local_port')
IPS_SCAN_RESULTS = _namedtuple('ips_scan_results', 'initial_block scan_detected block_status')
IPS_LOG = _namedtuple('ips_log', 'ip protocol attack_type action')
IPS_TRACKERS = _namedtuple('ips_trackers', 'lock tracker')

#IP PROXY
IPP_IP_INFO = _namedtuple('ipp_ip_info', 'tracked_ip local_ip')
IPP_INSPECTION_RESULTS = _namedtuple('ipp_inspection_results', 'category action')
IPP_LOG = _namedtuple('ipp_log', 'local_ip tracked_ip category direction action')

IPP_SRC_INFO = _namedtuple('src_info', 'protocol src_ip src_port')
IPP_DST_INFO = _namedtuple('dst_info', 'protocol dst_ip dst_port')

#INFECTED CLIENTS
INFECTED_LOG = _namedtuple('infected_log', 'infected_client src_ip detected_host reason')

#DATABASE
BLOCKED_DOM = _namedtuple('blocked', 'domain category reason')

#SOCKET
L_SOCK   = _namedtuple('l_sock', 'socket intf')
NFQ_SOCK = _namedtuple('socket_info', 'zone name mac ip sock')

# BYTE CONTAINERS
# ----------------
RESOURCE_RECORD = _ByteContainer('resource_record', 'name qtype qclass ttl data')
