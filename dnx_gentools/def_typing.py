#!/usr/bin/env python3

from __future__ import annotations
from typing import TYPE_CHECKING

DISABLED = True

from typing import *

# NOTE: splitting if statements as import organization
# standard lib imports
if (TYPE_CHECKING and not DISABLED):

    from ipaddress import IPv4Address

    Wrapper = Callable([...], None)

    FileLock = NewType('FileLock', type('LOCK'))
    WebError = NewType('WebError', dict[str, Union[int, str]])

# dnx class imports for use as Types
if (TYPE_CHECKING and not DISABLED):

    # module packs
    from dnx_gentools import *
    from dnx_routines import *
    from dnx_secmods import *
    from dnx_netmods import *
    from dnx_webui import *

    ProxyCallback = Callable[..., None]
    ProxyPacket = Union[[IPPPacket, IPSPacket, DNSPacket], None]
    ProxyParser = Callable[[CPacket, int], ProxyPacket]

    DNSListHandler = Callable[[Any, str, int], int]

    Structure = dict[str, int]

    ObjectManager = ob
