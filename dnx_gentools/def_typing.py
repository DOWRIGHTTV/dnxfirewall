#!/usr/bin/env python3

from __future__ import annotations
from typing import TYPE_CHECKING, Callable, Generator, Iterator, Type, NewType, ClassVar, Literal, Union, Optional, Any

_DISABLED = False

# NOTE: splitting if statements as import organization
# standard lib imports
if (TYPE_CHECKING and not _DISABLED):

    from threading import Lock
    from ipaddress import IPv4Address

    Wrapper = Callable[[Any], None]

    ConfigLock = NewType('ConfigLock', type('FileLock'))
    IPTableLock = NewType('IPTableLock', type('FileLock'))
    WebError = dict[str, Union[int, str]]

# dnx class imports for use as Types
if (TYPE_CHECKING and not _DISABLED):

    # module packs
    from dnx_gentools import *
    from dnx_routines import *
    from dnx_secmods import *
    from dnx_netmods import *
    from dnx_webui import *

    ProxyCallback = Callable[[...], None]
    ProxyPacket = Union[IPPPacket, IPSPacket, DNSPacket, None]
    ProxyParser = Callable[[CPacket, int], ProxyPacket]

    DNSListHandler = Callable[[Any, str, int], int]

    Structure = dict[str, int]
