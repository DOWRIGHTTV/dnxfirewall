#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, Type

__all__ = (
    'DNSProxy', 'DNSServer',
    'ClientQuery', 'DNSPacket',
    'request_tracker', 'dns_cache',

    # TYPES
    'DNSServer_T', 'DNSPacket_T'
)

if (TYPE_CHECKING):

    # referencing some objects through proxy import references
    from dns_proxy import DNSProxy
    from dns_proxy_server import DNSServer
    from dns_proxy_packets import ClientQuery, DNSPacket
    from dns_proxy_cache import request_tracker, dns_cache

    # ======
    # TYPES
    # ======
    DNSServer_T = Type[DNSServer]
    DNSPacket_T = Type[DNSPacket]
