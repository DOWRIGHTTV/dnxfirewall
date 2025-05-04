#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_constants import TYPE_CHECKING
from dnx_gentools.def_enums import DIR_INBOUND

from dnx_iptools.packet_classes import NFPacket, RawResponse

if (TYPE_CHECKING):
    from dnx_gentools.def_typing import IP_ADDRINT


class IPPPacket(NFPacket):
    tracked_ip: IP_ADDRINT
    local_ip:   IP_ADDRINT

    __slots__ = (
        'tracked_ip', 'local_ip',
    )

    def _before_exit(self, mark: int) -> None:

        if (self.direction == DIR_INBOUND):
            self.tracked_ip = self.src_ip
            self.local_ip = self.dst_ip

        # elif self.direction = DIR.OUTBOUND:
        else:
            self.tracked_ip = self.dst_ip
            self.local_ip = self.src_ip


# RawResponse can only be subclassed and not used directly.
class ProxyResponse(RawResponse):
    pass
