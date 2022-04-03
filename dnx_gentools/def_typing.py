#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, cast, Type, NewType, Literal, Protocol, Callable, Generator, Iterator, Iterable
from typing import ClassVar, Union, Optional, Any, NoReturn, ByteString

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

    Wrapper = Callable[[Any], None]
    Callable_T = Callable[[Any, ...], Any]

    ConfigLock = NewType('ConfigLock', type('FileLock'))
    IPTableLock = NewType('IPTableLock', type('FileLock'))
    WebError = dict[str, Union[int, str]]

    # dnx class imports for use as Types

    # module packs
    from dnx_gentools.def_namedtuples import L_SOCK as _L_SOCK
    # from dnx_iptools import *
    # from dnx_routines import *

    from dnx_secmods import IPProxy_T, IPS_IDS_T, DNSProxy_T
    from dnx_secmods import ClientQuery as _ClientQuery
    from dnx_secmods import IPPPacket as _IPPPacket, IPSPacket as _IPSPacket
    from dnx_secmods import DNSPacket as _DNSPacket

    from dnx_netmods import DHCPServer_T
    from dnx_netmods import CPacket as _CPacket, ClientRequest as _ClientRequest

    from dnx_iptools.packet_classes import NFPacket as _NFPacket

    ModuleClasses = Union[IPProxy_T, IPS_IDS_T, DNSProxy_T, DHCPServer_T]

    ListenerCallback = Callable[..., None]
    ListenerPackets = Union[_ClientRequest, _ClientQuery]
    ListenerParser = Callable[[Address, _L_SOCK], ListenerPackets]

    ProxyCallback = Callable[..., None]
    ProxyPackets = Union[_IPPPacket, _IPSPacket, _DNSPacket, _NFPacket]
    ProxyParser = Callable[[_CPacket, int], ProxyPackets]

    DNSListHandler = Callable[[Any, str, int], int]

