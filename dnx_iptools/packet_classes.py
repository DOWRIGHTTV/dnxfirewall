#!/usr/bin/env python3

from __future__ import annotations

import time
import traceback
import socket
import select
import threading

from dnx_gentools.def_constants import *
from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import PROTO
from dnx_gentools.standard_tools import looper
from dnx_gentools.def_namedtuples import RELAY_CONN, NFQ_SEND_SOCK, L_SOCK

from dnx_iptools.def_structs import *
from dnx_iptools.def_structures import *
from dnx_iptools.protocol_tools import itoip, calc_checksum
from dnx_iptools.interface_ops import load_interfaces, wait_for_interface, wait_for_ip, get_masquerade_ip

from dnx_netmods.dnx_netfilter.dnx_nfqueue import NetfilterQueue, set_user_callback as set_nfqueue_callback

__all__ = (
    'Listener', 'ProtoRelay', 'NFQueue', 'NFPacket', 'RawPacket', 'RawResponse'
)

def _NOT_IMPLEMENTED(*args, **kwargs):
    raise NotImplementedError('subclass must reference a data handling function.')


class Listener:
    __registered_socks: ClassVar[dict] = {}
    __epoll = select.epoll()

    _Log: ClassVar[LogHandler_T] = None
    _packet_parser: ClassVar[ProxyParser] = _NOT_IMPLEMENTED
    _proxy_callback: ClassVar[ProxyCallback] = _NOT_IMPLEMENTED

    _intfs: ClassVar[list[tuple[int, int, str]]] = load_interfaces(exclude=['wan'])

    # stored as file descriptors to minimize lookups in listener queue.
    enabled_intfs: ClassVar[set] = set()

    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        if (cls is Listener):
            raise TypeError('Listener can only be used via inheritance.')

        return object.__new__(cls)

    @classmethod
    def run(cls, Log: LogHandler_T, *, threaded: bool = True, always_on: bool = False):
        '''associating subclass Log reference with Listener class. registering all interfaces in _intfs and starting
        service listener loop. calling class method setup before to provide subclass specific code to run at class level
        before continuing.'''

        Log.informational(f'{cls.__name__} initialization started.')

        cls._Log = Log

        # child class hook to initialize higher level systems. NOTE: must stay after initial intf registration
        cls._setup()

        # starting a registration thread for all available interfaces and exit when complete
        for intf in cls._intfs:
            threading.Thread(target=cls.__register, args=(intf,)).start()

        # ======================
        # INITIALIZING LISTENER
        # ======================
        # running main epoll/ socket loop.
        self = cls()
        self.__listener(always_on, threaded)

    @classmethod
    def enable(cls, sock_fd: int, intf: str):
        '''adds a file descriptor id to the disabled interface set.

        this effectively re-enables the server for the zone of the specified socket.'''

        cls.enabled_intfs.add(sock_fd)

        cls._Log.notice(f'[{sock_fd}][{intf}] {cls.__name__} listener enabled.')

    @classmethod
    def disable(cls, sock_fd: int, intf: str):
        '''removes a file descriptor id to the disabled interface set.

        this effectively disables the server for the zone of the specified socket.'''

        # try block is to prevent key errors on initialization. after that, key errors should not be happening.
        try:
            cls.enabled_intfs.remove(sock_fd)
        except KeyError:
            pass

        cls._Log.notice(f'[{sock_fd}][{intf}] {cls.__name__} listener disabled.')

    @classmethod
    def _setup(cls):
        '''called prior to creating listener interface instances.

        module wide code can be run here. May be overridden.

        '''
        pass

    @classmethod
    # TODO: what happens if interface comes online, then immediately gets unplugged. the registration would fail
    #  potentially and would no longer be active so it would never happen if the interface was replugged after.
    def __register(cls, intf: tuple[int, int, str]):
        '''will register interface with the listener.

        requires subclass property for listener_sock returning a valid socket object. once registration is complete the
        thread will exit.'''

        # this is being defined here so the listener will be able to correlate socket back to interface and send in.
        # NOTE: we can probably _ the first 2 vars, but they may actually come in handy for something so check to see
        # if they can be used to simplify the file descriptor tracking we had to implement awhile back.
        intf_index, zone, _intf = intf

        cls._Log.debug(f'[{_intf}] {cls.__name__} started interface registration.')

        wait_for_interface(interface=_intf)
        intf_ip = wait_for_ip(interface=_intf)

        l_sock = cls.listener_sock(_intf, intf_ip)
        cls.__registered_socks[l_sock.fileno()] = L_SOCK(
            _intf, intf_ip, l_sock, l_sock.send, l_sock.sendto, l_sock.recvfrom_into
        )

        cls.__epoll.register(l_sock.fileno(), select.EPOLLIN)

        cls._Log.informational(f'[{l_sock.fileno()}][{intf}] {cls.__name__} interface registered.')

    @classmethod
    def set_proxy_callback(cls, *, func: ProxyCallback):
        '''takes a callback function to handle packets after parsing. the reference will be called
        as part of the packet flow with one argument passed in for "packet".'''

        if (not callable(func)):
            raise TypeError('proxy callback must be a callable object.')

        cls._proxy_callback = func

    def __listener(self, always_on: bool, threaded: bool):

        # assigning all attrs as a local var for perf
        epoll_poll = self.__epoll.poll
        registered_socks_get = self.__registered_socks.get

        # methods
        packet_parser  = self._packet_parser
        proxy_callback = self._proxy_callback
        pre_inspect = self._pre_inspect

        # flags
        enabled_intfs = self.enabled_intfs

        # data buffer
        recv_buf: bytearray = bytearray(2048)
        recv_buffer = memoryview(recv_buf)

        # custom iterator
        for _ in RUN_FOREVER:
            l_socks = epoll_poll()
            for fd, _ in l_socks:

                sock_info = registered_socks_get(fd)
                try:
                    nbytes, address = sock_info.recvfrom(recv_buffer)
                except OSError:
                    continue

                # this is being used as a mechanism to disable/enable interface listeners
                # NOTE: since this portion is sequential, we can utilize memory view throughout the initial parse
                if (always_on or fd in enabled_intfs):
                    packet = packet_parser(address, sock_info)
                    try:
                        packet.parse(recv_buffer[:nbytes])
                    except:
                        traceback.print_exc()
                        continue

                    # referring to child class for whether to continue processing the packet
                    if not pre_inspect(packet):
                        return

                    if (threaded):
                        threading.Thread(target=proxy_callback, args=(packet,)).start()
                    else:
                        proxy_callback(packet)

                else:
                    self._Log.debug(f'recv on fd: {fd} | enabled ints: {self.enabled_intfs}')

    def _pre_inspect(self, packet):
        '''handle the request after the packet is parsed and confirmed a protocol match.

        Must be overridden.

        '''
        raise NotImplementedError('the _pre_inspect method must be overridden in subclass.')

    @staticmethod
    def listener_sock(intf: str, intf_ip: IPv4Address):
        '''returns instance level listener socket.

        Must be overridden.

        '''
        raise NotImplementedError('the listener_sock method must be overridden in subclass.')


class ProtoRelay:
    '''parent class for udp and tls relays.

    provides standard built in methods to start, check status, or add jobs to the work queue. _dns_queue object must
    be overwritten by subclasses.'''

    _protocol: ClassVar[PROTO] = PROTO.NOT_SET

    __slots__ = (
        '_dns_server', '_fallback_relay',

        '_relay_conn', '_send_cnt', '_last_rcvd',
        '_responder_add', '_fallback_relay_add'
    )

    def __new__(cls, *args, **kwargs):
        if (cls is ProtoRelay):
            raise TypeError('ProtoRelay can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self, dns_server: Type[DNSServer], fallback_relay: Optional[Callable]):
        '''general constructor. can only be reached through subclass.

        May be expanded.

        '''
        self._dns_server = dns_server
        self._fallback_relay = fallback_relay

        # dummy sock setup
        sock = socket.socket()
        self._relay_conn = RELAY_CONN(None, sock, sock.send, sock.recv, None)

        self._send_cnt  = 0
        self._last_rcvd = 0

        # direct reference for performance
        if (fallback_relay):
            self._fallback_relay_add = fallback_relay.add

    @classmethod
    def run(cls, dns_server: Type[DNSServer], *, fallback_relay: Optional[Callable] = None):
        '''starts the protocol relay.

        DNSServer object is the class handling client side requests which we can call back to and fallback is a
        secondary relay that can get forwarded a request post failure. initialize will be called to run any subclass
        specific processing then query handler will run indefinitely.'''
        self = cls(dns_server, fallback_relay)

        threading.Thread(target=self._fail_detection).start()
        Thread(target=self.relay).start()

    def relay(self):
        '''main relay process for handling the relay queue. will block and run forever.'''

        raise NotImplementedError('relay must be implemented in the subclass.')

    def _send_query(self, send_data: bytearray, request: str) -> None:
        for attempt in ATTEMPTS:
            try:
                self._relay_conn.send(send_data)
            except OSError:

                if not self._register_new_socket(): break

                threading.Thread(target=self._recv_handler).start()

            else:
                self._increment_fail_detection()

                # NOTE: temp | identifying connection version to terminal. when removing consider having the relay
                # protocol show in the webui > system reports.
                console_log(
                    f'[{self._relay_conn.remote_ip}/{self._relay_conn.version}][{attempt}] Sent {request}'
                )

                break

    def _recv_handler(self):
        '''called in a thread after creating new socket to handle all responses from remote server.'''

        raise NotImplementedError('_recv_handler method must be overridden in subclass.')

    def _register_new_socket(self):
        '''logic to create socket object used for external dns queries.'''

        raise NotImplementedError('_register_new_socket method must be overridden in subclass.')

    @looper(FIVE_SEC)
    def _fail_detection(self):
        if (fast_time() - self._last_rcvd >= FIVE_SEC and self._send_cnt >= HEARTBEAT_FAIL_LIMIT):
            self.mark_server_down()

    # processes that were unable to connect/ create a socket will send in the remote server ip that was attempted.
    # if a remote server isn't specified the active relay socket connection's remote ip will be used.
    def mark_server_down(self, *, remote_server: str = None):
        if (not remote_server):
            remote_server = self._relay_conn.remote_ip

        # more likely case is primary server going down so will use as baseline condition
        primary = self._dns_server.dns_servers.primary

        # if servers could change during runtime, this has a slight race condition potential, but it shouldn't matter
        # because when changing a server it would be initially set to down (essentially a no-op)
        server = primary if primary['ip'] == remote_server else self._dns_server.dns_servers.secondary
        server[PROTO.DNS_TLS] = True

        try:
            self._relay_conn.sock.close()
        except OSError:
            console_log(f'[{self._relay_conn.remote_ip}] Failed to close socket while marking server down.')

    def _increment_fail_detection(self):
        self._send_cnt += 1

    @property
    def is_enabled(self) -> bool:
        '''set as true if the running classes protocol matches the currently configured protocol.'''

        return self._dns_server.protocol is self._protocol

    @property
    def fail_condition(self) -> bool:
        '''property to streamline fallback action if condition is met. returns False by default.

        May be overridden.

        '''
        return False


class NFQueue:
    _log: ClassVar[LogHandler_T] = None
    _packet_parser: ClassVar[ProxyParser] = _NOT_IMPLEMENTED
    _proxy_callback: ClassVar[ProxyCallback] = _NOT_IMPLEMENTED

    __slots__ = (
        '__q_num', '__threaded'
    )

    def __new__(cls, *args, **kwargs):
        if (cls is NFQueue):
            raise TypeError('NFQueue can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self):
        '''Constructor. can only be reached if called through subclass.

        May be extended.

        '''
        self.__q_num = None
        self.__threaded = None

    @classmethod
    def run(cls, Log: LogHandler_T, *, q_num: int, threaded: bool = True) -> None:
        cls._setup()
        cls._log = Log

        self = cls()
        self.__q_num = q_num
        self.__threaded = threaded
        self.__queue()

    @classmethod
    def _setup(cls):
        '''called prior to creating listener interface instances. module wide code can be run here.

        May be overridden.

        '''
        pass

    @classmethod
    def set_proxy_callback(cls, *, func: ProxyCallback) -> None:
        '''Takes a callback function to handle packets after parsing.

        the reference will be called as part of the packet flow with one argument passed in for "packet".'''

        if (not callable(func)):
            raise TypeError('Proxy callback must be a callable object.')

        cls._proxy_callback = func

    def __queue(self) -> None:
        set_nfqueue_callback(self.__handle_packet)

        for _ in RUN_FOREVER:
            nfqueue = NetfilterQueue()
            nfqueue.nf_set(self.__q_num)

            self._log.notice('Starting dnx_netfilter queue. Packets will be processed shortly')

            # this is a blocking call that interacts with the system via callback. the while loop is to re-establish the
            # queue handle after an uncaught exception (hopefully maintaining system uptime)
            try:
                nfqueue.nf_run()
            except:
                nfqueue.nf_break()

                self._log.alert('Netfilter binding lost. Attempting to rebind.')

            time.sleep(1)

    def __handle_packet(self, nfqueue: CPacket, mark: int):
        try:
            packet = self._packet_parser(nfqueue, mark)
        except:
            nfqueue.drop()

            traceback.print_exc()
            self._log.error('failed to parse CPacket. Packet discarded.')

        else:
            if self._pre_inspect(packet):
                if (self.__threaded):
                    threading.Thread(target=self._proxy_callback, args=(packet,)).start()
                else:
                    self._proxy_callback(packet)

    def _pre_inspect(self, packet) -> bool:
        '''a method automatically called after packet parsing.

        used to determine the course of action for a packet. nfqueue drop, accept, or repeat can be called within this
        scope. return will be checked as a boolean, where True will continue and False will do nothing.

        May be overridden.

        '''
        return True


class NFPacket:

    __slots__ = (
        'nfqueue', 'mark',

        'in_zone', 'out_zone',
        'src_mac', 'timestamp',

        # ip header
        'ip_header', 'protocol',
        'src_ip', 'dst_ip',

        # proto headers
        'udp_header',
        'src_port', 'dst_port',

        # tcp
        'seq_number', 'ack_number',

        # udp
        'udp_header', 'udp_payload',

        # icmp
        'icmp_type'
    )

    @classmethod
    def netfilter_recv(cls, cpacket: CPacket, mark: int) -> NFPacket:
        '''Cython > Python attribute conversion'''

        self = cls()

        # reference to allow higher level modules to call packet actions directly
        self.nfqueue = cpacket

        # creating isntance attr so it can be modified if needed
        self.mark = mark

        hw_info = cpacket.get_hw()
        self.in_zone   = hw_info[0]
        self.out_zone  = hw_info[1]
        self.src_mac   = hw_info[2]
        self.timestamp = hw_info[3]

        ip_header = cpacket.get_ip_header()
        self.protocol = PROTO(ip_header[6])
        self.src_ip = ip_header[8]
        self.dst_ip = ip_header[9]

        if (self.protocol is PROTO.TCP):
            proto_header = cpacket.get_tcp_header()

            self.src_port   = proto_header[0]
            self.dst_port   = proto_header[1]
            self.seq_number = proto_header[2]
            self.ack_number = proto_header[3]

        elif (self.protocol is PROTO.UDP):
            proto_header = cpacket.get_udp_header()

            self.src_port = proto_header[0]
            self.dst_port = proto_header[1]

            # ip/udp header are only needed for icmp response payloads [at this time]
            # packing into bytes to make icmp response generation more streamlined if needed
            self.ip_header = bytearray(20)
            self.udp_header = bytearray(8)

            iphdr_pack_into(self.ip_header, 0, *ip_header)
            udphdr_pack_into(self.udp_header, 0, *proto_header)

            # data payload used by IPS/IDS (portscan detection) and DNSProxy
            self.udp_payload = cpacket.get_payload()

        elif (self.protocol is PROTO.ICMP):
            proto_header = cpacket.get_icmp_header()

            self.icmp_type = ICMP(proto_header[0])

        # subclass hook
        self._before_exit(mark)

        return self

    def _before_exit(self, mark):
        '''executes before returning from parse call.

        May be overridden.

        '''
        pass


class RawPacket:
    '''NOTICE: this class has been significantly reduced in use. [no current modules subclassing]

    parent class designed to index/parse full tcp/ip packets (including ethernet). alternate
    constructors are supplied to support different listener types e.g. raw sockets.

    raw socket:
        packet = RawPacket.interface(data, address, socket)

    the before_exit method can be overridden to extend the parsing functionality, for example to group
    objects in namedtuples or to index application data.

    '''

    __slots__ = (
        '_addr', 'protocol',

        # init vars
        'data', 'timestamp',
        'sendto', 'intf_ip',

        # ip
        'ip_header', 'src_ip', 'dst_ip',
        'src_port', 'dst_port',

        # tcp
        'seq_number', 'ack_number',

        # udp
        'udp_chk', 'udp_len',
        'udp_header', 'udp_payload',

        # icmp
        'icmp_type'
    )

    def __new__(cls, *args, **kwargs):
        if (cls is RawPacket):
            raise TypeError('RawPacket can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self):
        '''general default var assignments. not intended to be called directly.

        May be expanded.

        '''
        self.timestamp = fast_time()

        # NOTE: recently moved these here. they are defined in the parents slots, so it makes sense. I think these were
        # in the child (ips) because the ip proxy does not need these initialized.
        self.icmp_type = None
        self.udp_payload = b''

    @classmethod
    def interface(cls, address, sock_info):
        '''alternate constructor. used to start listener/proxy instances bound to physical interfaces(active socket).'''

        self = cls()
        self._addr = address  # TODO: see if this can be removed

        # intf_ip used to fill sinkhole query response with rules interface ip (of intf received on)
        self.intf_ip = sock_info[1].packed
        self.sendto  = sock_info[4]

        return self

    def parse(self, data):
        '''index tcp/ip packet layers 3 & 4 for use as instance objects.

        the before_exit method will be called before returning. this can be used to create
        subclass specific objects like namedtuples or application layer data.'''

        self.protocol = PROTO(data[9])
        self.src_ip, self.dst_ip = ip_addrs_unpack(data[12:20])

        # calculating iphdr len then slicing out
        data = data[(data[0] & 15) * 4:]

        if (self.protocol is PROTO.ICMP):
            self.icmp_type = data[0]

        else:

            self.src_port, self.dst_port = double_short_unpack(data[:4])

            # tcp header max len 32 bytes
            if (self.protocol is PROTO.TCP):

                self.seq_number, self.ack_number = double_long_unpack(data[4:8])

            # udp header 8 bytes
            elif (self.protocol is PROTO.UDP):

                self.udp_len, self.udp_chk = double_short_unpack(data[4:8])

                self.udp_header  = data[:8]
                self.udp_payload = data[8:]

        if (self.continue_condition):
            self._before_exit()

    def _before_exit(self):
        '''executes before returning from parse call.

        May be overridden.

        '''
        pass

    @property
    def continue_condition(self) -> bool:
        '''controls whether the _before_exit method gets called.

        May be overridden.

        '''
        return True


# ==========================
# PROXY RESPONSE BASE CLASS
# ==========================
# pre-defined fields which are functionally constants for the purpose of connection resets
_ip_header_template = PR_IP_HDR(**{'ver_ihl': 69, 'tos': 0, 'ident': 0, 'flags_fro': 16384, 'ttl': 255, 'checksum': 0})
_tcp_header_template = PR_TCP_HDR(**{'seq_num': 696969, 'offset_control': 20500, 'window': 0, 'urg_ptr': 0})
_pseudo_header_template = PR_TCP_PSEUDO_HDR(**{'reserved': 0, 'protocol': 6, 'tcp_len': 20})
_icmp_header_template = PR_ICMP_HDR(**{'type': 3, 'code': 3, 'unused': 0})

class RawResponse:
    '''base class for managing raw socket operations for sending data only. interfaces will be registered
    on startup to associate interface, zone, mac, ip, and active socket.'''

    __setup: ClassVar[bool] = False
    _log: ClassVar[LogHandler_T] = None
    _Module = None

    _registered_socks: ClassVar[dict] = {}

    # dynamically provide interfaces. default returns builtins.
    _intfs = load_interfaces()

    __slots__ = (
        '_packet',
    )

    def __new__(cls, *args, **kwargs):
        if (cls is RawResponse):
            raise TypeError('RawResponse can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self, packet: ProxyPacket):
        self._packet = packet

    @classmethod
    def setup(cls, log: LogHandler_T, Module) -> None:
        '''register all available interfaces in a separate thread for each. registration will wait for the interface to
        become available before finalizing.'''

        if (cls.__setup):
            raise RuntimeError('response handler setup can only be called once per process.')

        cls.__setup = True

        cls._log = log
        cls._Module = Module

        # direct assignment for perf
        cls._open_ports = Module.open_ports
        cls._registered_socks_get = cls._registered_socks.get

        for intf in cls._intfs:
            threading.Thread(target=cls.__register, args=(intf,)).start()

    @classmethod
    def __register(cls, intf: tuple[int, int, str]):
        '''will register interface with ip and socket. a new socket will be used every time this method is called.'''
        intf_index, zone, _intf = intf

        wait_for_interface(interface=_intf)
        ip = wait_for_ip(interface=_intf)

        # sock sender is the direct reference to the socket send/to method, adding zone into value for easier
        # reference in prepare and send method.
        cls._registered_socks[intf_index] = NFQ_SEND_SOCK(zone, ip, cls.sock_sender())

        cls._log.informational(f'{cls.__name__}: {_intf} registered.')

    @classmethod
    def prepare_and_send(cls, packet: ProxyPacket):
        '''obtains socket object based on interface/zone received then prepares a raw packet (all layers).
        internal _send method will be called once finished.

        Do not override.

        '''

        self = cls(packet)

        # in_zone is actually interface index, but zones are linked through this identifier
        intf = self._registered_socks_get(packet.in_zone)

        # NOTE: if the wan interface has a static ip address we can use the ip assigned during registration.
        # this will need a condition to check, but won't need to masquerade.
        dnx_src_ip = packet.dst_ip if intf.zone != WAN_IN else get_masquerade_ip(dst_ip=packet.src_ip)

        # calling hook for packet generation. this can be overloaded by subclass.
        send_data = self._prepare_packet(packet, dnx_src_ip)
        try:
            intf.sock_sendto(send_data, (itoip(packet.src_ip), 0))
        except OSError:
            pass

    def _prepare_packet(self, packet: ProxyPacket, dnx_src_ip: int) -> bytearray:
        # checking if dst port is associated with a nat. if so, will override necessary fields based on protocol
        # and re-assign in the packet object
        # NOTE: can we please optimize this. PLEASE!
        port_override = self._open_ports[packet.protocol].get(packet.dst_port)
        if (port_override):
            self._packet_override(packet, dnx_src_ip, port_override)

        # TCP HEADER
        if (packet.protocol is PROTO.TCP):
            response_protocol = PROTO.TCP

            # new instance of header byte container template
            protohdr = _tcp_header_template()

            # assigning missing fields
            protohdr.dst_port = packet.dst_port
            protohdr.src_port = packet.src_port
            protohdr.ack_num  = packet.seq_number + 1

            proto_header = protohdr.assemble()

            # using creation/call to handle field update and buffer assembly
            pseudo_header = _pseudo_header_template({'src_ip': dnx_src_ip, 'dst_ip': packet.src_ip})

            # calculating checksum of container
            proto_header[16:18] = calc_checksum(pseudo_header.buf + proto_header)

            proto_len = 20

        # ICMP HEADER
        # elif (packet.protocol is PROTO.UDP):
        else:
            response_protocol = PROTO.ICMP

            # new instance of header byte container template
            proto_header = _icmp_header_template()

            # per icmp, ip header and first 8 bytes of rcvd payload are included in icmp response payload
            icmp_payload = packet.ip_header + packet.udp_header

            # icmp pre-assemble covers this
            proto_header[2:4] = calc_checksum(proto_header + icmp_payload, pack=True)

            proto_len = 8 + 28

        # IP HEADER
        iphdr = _ip_header_template()

        iphdr.tl = 20 + proto_len
        iphdr.protocol = response_protocol
        iphdr.src_ip = dnx_src_ip
        iphdr.dst_ip = packet.src_ip

        ip_header = iphdr.assemble()
        ip_header[10:12] = calc_checksum(ip_header, pack=True)

        # ASSEMBLY
        send_data = ip_header + proto_header

        if (response_protocol is PROTO.ICMP):
            send_data += icmp_payload

        return send_data

    @staticmethod
    def _packet_override(packet: ProxyPacket, dnx_src_ip: int, port_override: int):
        if (packet.protocol is PROTO.TCP):
            packet.dst_port = port_override

        # in byte form since they are included in icmp payload in raw form
        elif (packet.protocol is PROTO.UDP):
            packet.udp_header[2:4] = short_pack(port_override)

            # NOTE: did we skip udp checksum because its not required?? prob should do it to be "legit"... someday

            # slicing operations will change the referenced object directly
            ip_header = packet.ip_header

            ip_header[10:12] = b'\x00\x00'
            ip_header[12:16] = long_pack(packet.src_ip)
            ip_header[16:20] = long_pack(dnx_src_ip)

            ip_header[10:12] = calc_checksum(ip_header, pack=True)

    @staticmethod
    def sock_sender():
        '''returns new socket object to be used with interface registration.

        May be overridden.

        '''
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        return sock.sendto
