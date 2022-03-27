#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_enums import DIR

from dnx_iptools.packet_classes import NFPacket, RawResponse
from dnx_iptools.cprotocol_tools import itoip


class IPPPacket(NFPacket):

    __slots__ = (
        'tracked_ip', 'local_ip',
    )

    def _before_exit(self, mark):

        if (self.direction == DIR.INBOUND):
            self.tracked_ip = itoip(self.src_ip)
            self.local_ip = itoip(self.dst_ip)

        # elif self.direction = DIR.OUTBOUND:
        else:
            self.tracked_ip = itoip(self.dst_ip)
            self.local_ip = itoip(self.src_ip)

# RawResponse can only be subclassed and not used directly.
class ProxyResponse(RawResponse):
    pass
