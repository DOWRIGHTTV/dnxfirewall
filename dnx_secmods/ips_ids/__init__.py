#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = (
    'IPS_IDS', 'IPSPacket'
)

if (TYPE_CHECKING):

    from ips_ids import IPS_IDS
    from ips_ids_packets import IPSPacket
