#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_constants import MSB, LSB
from dnx_gentools.def_enums import CONN, DIR

from dnx_iptools.packet_classes import NFPacket, RawResponse
from dnx_iptools.protocol_tools import int_to_ip


class IPPPacket(NFPacket):

    __slots__ = (
        'direction', 'action', 'tracked_geo',
        'ipp_profile', 'dns_profile', 'ips_profile',

        'local_ip', 'bin_data',
    )

    def _before_exit(self, mark):

        # X | X | ips (4b) | dns (4b) | ipp (4b) | geoloc (8b) | direction (2b) | action (2b)

        self.action    = CONN(mark & 3)
        self.direction =  DIR(mark >> 2 & 3)

        self.tracked_geo = mark >>  4 & 255
        self.ipp_profile = mark >> 12 & 15
        self.dns_profile = mark >> 16 & 15
        self.ips_profile = mark >> 20 & 15

        if (self.direction == DIR.INBOUND):
            tracked_ip = self.src_ip

            self.local_ip = int_to_ip(self.dst_ip)

        # elif self.direction = DIR.OUTBOUND:
        else:
            tracked_ip = self.dst_ip

            self.local_ip = int_to_ip(self.src_ip)

        self.bin_data = (tracked_ip & MSB, tracked_ip & LSB)

# NOTE: RawResponse can only be subclassed and not used directly.
class ProxyResponse(RawResponse):
    pass
