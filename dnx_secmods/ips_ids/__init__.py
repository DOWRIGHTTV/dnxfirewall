#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, Type

if (TYPE_CHECKING):
    __all__ = (
        'IPS_IDS', 'IPSPacket',

        # TYPES
        'IPS_IDS_T', 'IPSPacket_T'
    )

    from ips_ids import IPS_IDS
    from ips_ids_packets import IPSPacket

    # ======
    # TYPES
    # ======
    IPS_IDS_T = Type[IPS_IDS]
    IPSPacket_T = Type[IPSPacket]
