#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = (
    'IPProxy', 'IPPPacket'
)

if (TYPE_CHECKING):

    from ip_proxy import IPProxy
    from ip_proxy_packets import IPPPacket
