#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, cast, Type, NewType, Literal, Protocol, Callable, Generator, Iterator, Iterable
from typing import ClassVar, Union, Optional, Any, NoReturn, ByteString, TextIO

# import dnx_gentools

_DISABLED = False

# NOTE: splitting if statements as import organization
# standard lib imports
if (TYPE_CHECKING and not _DISABLED):
    from typing import TypeAlias, cast

    from threading import Lock as _Lock, Event as _Event
    from socket import socket as _socket
    from select import epoll as _epoll
    from ssl import SSLContext

    Lock_T: TypeAlias = _Lock  # todo: _T should only be used on Type[...] objects. figure out alternative.
    Event_T: TypeAlias = _Event
    Socket_T: TypeAlias = _socket
    Epoll_T: TypeAlias = _epoll

    IP_ADDRESS = NewType('IP_ADDRESS', str)
    IP_ADDRINT = NewType('IP_ADDRINT', int)

    NET_PORT = NewType('NET_PORT', int)
    TCP_PORT = NewType('TCP_PORT', NET_PORT)
    UDP_PORT = NewType('UDP_PORT', NET_PORT)

    NET_ADDRESS: TypeAlias = tuple[IP_ADDRESS, NET_PORT]
    NET_ADDRINT: TypeAlias = tuple[IP_ADDRINT, NET_PORT]

    Wrapped_ReturnNone: TypeAlias = Callable[..., None]
    Callable_ReturnNone: TypeAlias = Callable[..., None]
    Wrapper: TypeAlias = Callable[..., None]

    Callable_T: TypeAlias = Callable[..., Any]

    StructUnpack: TypeAlias = tuple[int, ...]

    ConfigLock   = NewType('ConfigLock', type('FileLock'))  # verbose type str
    IPTablesLock = NewType('IPTablesLock', type('FileLock'))  # verbose type str
    FirewallDBLock = NewType('FirewallDBLock', type('FileLock'))  # verbose type str

    FileLock: TypeAlias = Union[ConfigLock, IPTablesLock, FirewallDBLock]

    # dnx class imports for use as Types

    # module packs
    from dnx_gentools.file_operations import ConfigChain, config
    from dnx_gentools.def_namedtuples import L_SOCK as _L_SOCK
    from dnx_gentools.def_enums import NETWORK_PROTOCOL
    # from dnx_iptools import *
    # from dnx_routines import *

    from dnx_secmods import IPProxy_T, IDS_IPS_T, DNSProxy_T, DNSCache_T
    from dnx_secmods import ClientQuery as _ClientQuery
    from dnx_secmods import IPPPacket as _IPPPacket, IPSPacket as _IPSPacket
    from dnx_secmods import DNSPacket as _DNSPacket

    from dnx_netmods import DHCPServer_T
    from dnx_netmods import CPacket as _CPacket, ClientRequest as _ClientRequest

    from dnx_iptools.packet_classes import NFPacket as _NFPacket

    ModuleClasses: TypeAlias = Union[IPProxy_T, IDS_IPS_T, DNSProxy_T, DHCPServer_T]

    ListenerCallback: TypeAlias = Callable[..., None]
    ListenerPackets:  TypeAlias = Union[_ClientRequest, _ClientQuery]
    ListenerParser:   TypeAlias = Callable[[Address, _L_SOCK], ListenerPackets]

    ProxyCallback: TypeAlias = Callable[..., None]
    ProxyPackets:  TypeAlias = Union[_IPPPacket, _IPSPacket, _DNSPacket, _NFPacket]
    ProxyParser:   TypeAlias = Callable[[_CPacket, int], ProxyPackets]

    DNSListHandler: TypeAlias = Callable[[Any, str, int], int]

    OPEN_WAN_PORTS: TypeAlias = dict[NETWORK_PROTOCOL, dict[int, int]]

    from dnx_gentools.def_namedtuples import INF_EVENT_LOG as _INF_EVENT_LOG
    from dnx_gentools.def_namedtuples import IPP_EVENT_LOG as _IPP_EVENT_LOG
    from dnx_gentools.def_namedtuples import IPS_EVENT_LOG as _IPS_EVENT_LOG
    from dnx_gentools.def_namedtuples import SigFile as _SigFile

    EVENT_LOGS: TypeAlias = Union[_IPP_EVENT_LOG, _IPS_EVENT_LOG, _INF_EVENT_LOG]

    SIGNATURE_MANIFEST: TypeAlias = list[_SigFile]
