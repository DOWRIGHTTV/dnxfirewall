#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, Type, NewType, Literal, Protocol, Callable, Generator, Iterator, ClassVar, Union
from typing import Optional, Any, NoReturn

_DISABLED = False

# NOTE: splitting if statements as import organization
# standard lib imports
if (TYPE_CHECKING and not _DISABLED):

    from threading import Lock, Event
    from ipaddress import IPv4Address as _IPv4Address, IPv4Network as _IPv4Network
    from socket import socket as Socket
    from select import epoll as Epoll
    from ssl import SSLContext

    Address = tuple[str, int]
    Structure = dict[str, int]

    Wrapper = Callable[[Any], None]
    Callable_T = Callable[[Any, ...], Any]

    ConfigLock = NewType('ConfigLock', type('FileLock'))
    IPTableLock = NewType('IPTableLock', type('FileLock'))
    WebError = dict[str, Union[int, str]]

    # dnx class imports for use as Types

    # module packs
    from dnx_gentools import *
    from dnx_iptools import *
    from dnx_routines import *
    from dnx_secmods import *
    from dnx_netmods import *
    from dnx_webui import *

    ListenerCallback = Callable[..., None]
    ListenerPackets = Union[ClientRequest, ClientQuery]
    ListenerParser = Callable[[Address, LI_SOCK], ListenerPackets]

    ProxyCallback = Callable[..., None]
    ProxyPackets = Union[IPPPacket, IPSPacket, DNSPacket]
    ProxyParser = Callable[[CPacket, int], ProxyPackets]

    DNSListHandler = Callable[[Any, str, int], int]
    DNSCache = dns_cache(dns_packet=DNSPacket, request_handler=Callable[[ClientQuery], None])
    RequestTracker = request_tracker()
