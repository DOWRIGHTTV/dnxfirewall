#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, cast, Type, NewType, Literal, Protocol, Callable, Generator, Iterator, Iterable
from typing import ClassVar, Union, Optional, Any, NoReturn, ByteString, TextIO

_DISABLED = False

# NOTE: splitting if statements as import organization
# standard lib imports
if (TYPE_CHECKING and not _DISABLED):
    from typing import TypeAlias, cast

    from threading import Lock as _Lock, Event as _Event
    from socket import socket as _socket
    from select import epoll as _epoll
    from ssl import SSLContext

    Lock_T: TypeAlias = _Lock
    Event_T: TypeAlias = _Event
    Socket_T: TypeAlias = _socket
    Epoll_T: TypeAlias = _epoll

    Address:    TypeAlias = tuple[str, int]
    IntAddress: TypeAlias = tuple[int, int]

    Wrapper: TypeAlias = Callable[[Any], None]
    Callable_T: TypeAlias = Callable[[Any, ...], Any]

    ConfigLock = NewType('ConfigLock', type('FileLock'))
    IPTableLock = NewType('IPTableLock', type('FileLock'))

    # dnx class imports for use as Types

    # module packs
    from dnx_gentools.file_operations import ConfigChain, config
    from dnx_gentools.def_namedtuples import L_SOCK as _L_SOCK
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

    StructUnpack: TypeAlias = tuple[int, ...]

    from dnx_gentools.def_namedtuples import INF_EVENT_LOG as _INF_EVENT_LOG
    from dnx_gentools.def_namedtuples import IPP_EVENT_LOG as _IPP_EVENT_LOG
    from dnx_gentools.def_namedtuples import IPS_EVENT_LOG as _IPS_EVENT_LOG
    from dnx_gentools.def_namedtuples import SigFile as _SigFile

    EVENT_LOGS: TypeAlias = Union[_IPP_EVENT_LOG, _IPS_EVENT_LOG, _INF_EVENT_LOG]

    SIGNATURE_MANIFEST: TypeAlias = list[_SigFile]
