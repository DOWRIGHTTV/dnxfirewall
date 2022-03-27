#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.standard_tools import structure as _structure

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Structure

# IP
PR_IP_HDR: Structure = _structure(
    'ip_header', 'B,ver_ihl B,tos H,tl H,ident H,flags_fro B,ttl B,protocol H,checksum L,src_ip L,dst_ip'
)

# TCP
PR_TCP_HDR: Structure = _structure(
    'tcp_header', 'H,dst_port H,src_port L,seq_num L,ack_num H,offset_control H,window H,checksum H,urg_ptr'
)
PR_TCP_PSEUDO_HDR: Structure = _structure('tcp_pseudo_header', 'L,src_ip L,dst_ip B,reserved B,protocol H,tcp_len')

# UDP
PR_UDP_HDR: Structure = _structure('udp_header', 'H,src_port H,dst_port H,len H,checksum')

# ICMP
PR_ICMP_HDR: Structure = _structure('udp_header', 'B,type B,code H,checksum L,unused')

# DNS
# resource record
DNS_STD_RR: Structure = _structure('resource_record', 'H,ptr H,type H,class L,ttl H,rd_len L,rd_data')
