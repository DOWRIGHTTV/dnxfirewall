#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_constants import MSB, LSB
from dnx_gentools.def_enums import CONN, DIR

from dnx_iptools.packet_classes import NFPacket, RawResponse
from dnx_iptools.cprotocol_tools import itoip


class IPPPacket(NFPacket):

    __slots__ = (
        'local_ip', 'tracked_ip', 'bin_data',
    )

    def _before_exit(self, mark):

        if (self.direction == DIR.INBOUND):
            tracked_ip = self.src_ip

            self.local_ip = itoip(self.dst_ip)

        # elif self.direction = DIR.OUTBOUND:
        else:
            tracked_ip = self.dst_ip

            self.local_ip = itoip(self.src_ip)

        self.tracked_ip = itoip(tracked_ip)
        self.bin_data = (tracked_ip & MSB, tracked_ip & LSB)

# NOTE: RawResponse can only be subclassed and not used directly.
class ProxyResponse(RawResponse):
    pass
