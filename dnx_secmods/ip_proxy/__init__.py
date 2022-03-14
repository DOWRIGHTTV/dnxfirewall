#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, Type

if (TYPE_CHECKING):
    __all__ = (
        'IPProxy', 'IPPPacket',

        # TYPES
        'IPProxy_T', 'IPPPacket_T'
    )

    from ip_proxy import IPProxy
    from ip_proxy_packets import IPPPacket

    # ======
    # TYPES
    # ======
    IPProxy_T = Type[IPProxy]
    IPPPacket_T = Type[IPPPacket]
