#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

if (TYPE_CHECKING):

    # referencing some objects through proxy import references
    from dns_proxy import DNSProxy, DNSServer
    from dns_proxy_cache import request_tracker, dns_cache
    from dns_proxy_packets import ClientQuery, DNSPacket
