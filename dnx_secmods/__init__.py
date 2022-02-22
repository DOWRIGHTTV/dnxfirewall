#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    # referencing some objects through proxy import references
    from cfirewall.fw_main import CFirewall

    from dns_proxy.dns_proxy import DNSProxy, DNSServer
    from dns_proxy.dns_proxy_cache import request_tracker, dns_cache
    from dns_proxy.dns_proxy_packets import ClientQuery, DNSPacket, ProxyPacket

    DNSCache = dns_cache(dns_packet=DNSPacket, request_handler=ProxyPacket)
    RequestTracker = request_tracker()

    from ip_proxy.ip_proxy import IPProxy
    from ip_proxy.ip_proxy_packets import IPPPacket

    from ips_ids.ips_ids import IPS_IDS
    from ips_ids.ips_ids_packets import IPSPacket
