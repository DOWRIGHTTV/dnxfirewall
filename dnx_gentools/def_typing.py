#!/usr/bin/env python3

from typing import TYPE_CHECKING

# NOTE: splitting if statements as import organization
# standard lib imports
if (TYPE_CHECKING):
    from typing import *

    from ipaddress import IPv4Address

# dnx class imports for use as Types
if (TYPE_CHECKING):

    # module packs
    from dnx_gentools import *
    from dnx_routines import *
    from dnx_secmods import *
    from dnx_netmods import *

ProxyCallback = Callable[..., None]
ProxyPacket   = Union[IPPPacket, IPSPacket, DNSPacket]
ProxyParser   = Callable[CPacket, int, ..., ProxyPacket]
