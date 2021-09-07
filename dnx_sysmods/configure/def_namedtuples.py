#!/usr/bin/env python3

from collections import namedtuple as _namedtuple

#DHCP SERVER
DHCP_REQUEST_INFO  = _namedtuple('dhcp_request_info' ,'message_type, xID, server_identifier, mac_address, client_address, requested_ip')
DHCP_RESPONSE_INFO = _namedtuple('dhcp_response_info', 'xID mac_address ciaddr handout_ip options')
DHCP_RECORD = _namedtuple('server_record', 'rtype timestamp mac hostname')

#SYSLOG CLIENT
SYSLOG_SERVERS = _namedtuple('syslog_servers', 'primary secondary')

#DNS PROXY
DNS_SERVERS = _namedtuple('dns_servers', 'primary secondary')
PROXY_DECISION = _namedtuple('proxy_decision', 'name decision')
RELAY_CONN = _namedtuple('relay_conn', 'remote_ip sock send recv version')
DNS_CACHE  = _namedtuple('dns_cache', 'ttl records')
CACHED_RECORD = _namedtuple('cached_record', 'expire ttl records')
DNS_REQUEST_INFO = _namedtuple('request_info', 'client_address request, request2')
DNS_REQUEST_RESULTS = _namedtuple('request_results', 'redirect, reason, category')
DNS_LOG = _namedtuple('dns_log', 'src_ip request category reason action')
BLOCKED_LOG = _namedtuple('blocked_log', 'src_ip request category reason action')

DNS_SIGNATURES = _namedtuple('signatures', 'en_dns tld keyword')
DNS_WHITELIST  = _namedtuple('whitelist', 'dns ip')
DNS_BLACKLIST  = _namedtuple('blacklist', 'dns')

# IPS
IPS_WAN_INFO = _namedtuple('ips_wan_info', 'interface ip mac')
IPS_SCAN_RESULTS = _namedtuple('ips_scan_results', 'initial_block scan_detected block_status')
IPS_LOG = _namedtuple('ips_log', 'ip protocol attack_type action')
PSCAN_TRACKERS = _namedtuple('portscan', 'lock tracker')
DDOS_TRACKERS  = _namedtuple('ddos', 'lock tracker')

#IP PROXY
IPP_INSPECTION_RESULTS = _namedtuple('ipp_inspection_results', 'category action')
IPP_LOG = _namedtuple('ipp_log', 'local_ip tracked_ip category direction action')
GEO_LOG = _namedtuple('geo_log', 'country direction action')

IPP_SRC_INFO = _namedtuple('src_info', 'protocol src_ip src_port')
IPP_DST_INFO = _namedtuple('dst_info', 'protocol dst_ip dst_port')

#INFECTED CLIENTS
INFECTED_LOG = _namedtuple('infected_log', 'infected_client src_ip detected_host reason')

#DATABASE
BLOCKED_DOM = _namedtuple('blocked', 'domain category reason')

#SOCKET
L_SOCK = _namedtuple('listener_socket', 'name ip socket send sendto recvfrom')
# NFQ_SOCK = _namedtuple('socket_info', 'zone name mac ip sock')
NFQ_SEND_SOCK = _namedtuple('socket_info', 'zone name ip sock_sendto')
