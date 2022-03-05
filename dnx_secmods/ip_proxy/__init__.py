#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, Type

__all__ = (
    'IPProxy', 'IPPPacket',

    # TYPES
    'IPPPacket_T'
)

if (TYPE_CHECKING):

    from ip_proxy import IPProxy
    from ip_proxy_packets import IPPPacket

    # ======
    # TYPES
    # ======
    IPPPacket_T = Type[IPPPacket]
