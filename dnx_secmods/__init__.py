#!/usr/bin/env python3

from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    # referencing some objects through proxy import references
    from dns_proxy.dns_proxy import DNSProxy, DNSServer
    from dns_proxy.dns_proxy_packets import ClientQuery
