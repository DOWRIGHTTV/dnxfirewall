#!/usr/bin/env python3

from __future__ import annotations

import traceback
import socket
import select

from threading import Thread

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import PROTO, ICMP, DECISION, DIRECTION
from dnx_gentools.def_exceptions import ProtocolError
from dnx_gentools.standard_tools import looper, inspection_queue
from dnx_gentools.def_namedtuples import RELAY_CONN, NFQ_SEND_SOCK, L_SOCK, DNS_SEND

from dnx_iptools.def_structs import *
from dnx_iptools.def_structures import *
from dnx_iptools.cprotocol_tools import itoip, calc_checksum
from dnx_iptools.interface_ops import load_interfaces, wait_for_interface, wait_for_ip, get_masquerade_ip

from dnx_netmods.dnx_netfilter.dnx_nfqueue import NetfilterQueue

if (TYPE_CHECKING):
    from dnx_netmods.dnx_netfilter import CPacket
    from dnx_secmods.dns_proxy import DNSServer_T
    from dnx_routines.logging import LogHandler_T

    from dnx_gentools import Structure_T

    from dnx_iptools.interface_ops import Intf, IntfList

__all__ = (
    'Listener', 'ProtoRelay', 'NFQueue', 'NFPacket', 'RawResponse'
)


class Listener:
    __registered_socks: ClassVar[dict[int, L_SOCK]] = {}
    __epoll: ClassVar[Epoll_T] = select.epoll()

    _intfs: ClassVar[IntfList] = load_interfaces(exclude=['wan'])
    _log:   ClassVar[LogHandler_T] = None

    _listener_parser:   ClassVar[ListenerParser]
    _listener_callback: ClassVar[ListenerCallback]

    # stored as file descriptors to minimize lookups in listener queue.
    enabled_intfs: set[int] = set()

    __slots__ = ()

    # TODO: what happens if interface comes online, then immediately gets unplugged. the registration would fail
    #  potentially and would no longer be active so it would never happen if the interface was replugged after.
    def __register(self, intf: Intf) -> None:
        '''registers an interface with the listener.

        once registration is complete the thread will exit.
        '''
        # this is being defined here so the listener will be able to correlate socket back to interface and send in.
        # NOTE: we can probably _ the first 2 vars, but they may actually come in handy for something so check to see
        #  if they can be used to simplify the file descriptor tracking we had to implement awhile back.
        intf_index, _intf, zone = intf

        self._log.debug(f'[{_intf}] {self.__class__.__name__} started interface registration.')

        wait_for_interface(interface=_intf)
        intf_ip = wait_for_ip(interface=_intf)

        l_sock = self._listener_sock(_intf, intf_ip)
        self.__class__.__registered_socks[l_sock.fileno()] = L_SOCK(
            _intf, intf_ip, l_sock, l_sock.send, l_sock.sendto, l_sock.recvfrom_into
        )

        self.__class__.__epoll.register(l_sock.fileno(), select.EPOLLIN)

        self._log.informational(f'[{l_sock.fileno()}][{intf}] {self.__class__.__name__} interface registered.')

    def __run_listener(self, always_on: bool) -> NoReturn:

        # assigning all attrs as a local var for perf
        epoll_poll = self.__epoll.poll
        registered_socks_get = self.__registered_socks.get
        request_handler_add = self.request_handler.add

        # methods
        listener_parser = self._listener_parser

        # flags
        enabled_intfs = self.enabled_intfs

        # data buffer
        recv_buf = bytearray(2048)
        recv_buffer = memoryview(recv_buf)

        nbytes: int
        address: Address

        # custom iterator
        for _ in RUN_FOREVER:
            l_socks = epoll_poll()
            for fd, _ in l_socks:

                sock_info: L_SOCK = registered_socks_get(fd)
                try:
                    nbytes, address = sock_info.recvfrom(recv_buffer)
                except OSError:
                    self._log.debug(f'recv error on socket: {sock_info}')
                    continue

                # this is being used as a mechanism to disable/enable interface listeners
                # NOTE: since this portion is sequential, we can utilize memory view throughout the initial parse
                if (always_on or fd in enabled_intfs):
                    packet: ListenerPackets = listener_parser(address, sock_info)
                    try:
                        packet.parse(recv_buffer[:nbytes])
                    except:
                        traceback.print_exc()
                        continue

                    request_handler_add(packet)

                else:
                    self._log.debug(f'recv on fd: {fd} | enabled ints: {self.enabled_intfs}')

    def _setup(self):
        '''called prior to creating listener interface instances.

        May be overridden.
        '''
        pass

    def _listener_sock(self, intf: str, intf_ip: int) -> Socket_T:
        '''returns instance level listener socket.

        Must be overridden.
        '''
        raise NotImplementedError('the listener_sock method must be overridden in subclass.')

    def request_handler(self, request: Any) -> None:
        '''must be overriden by the subclass and implemented with the dnx_queue decorator.

        example:
                @dnx_queue(Log, 'ModuleName')
                def request_handler(self, request: Any) -> None
                    ...
        '''
        raise NotImplementedError('the request_handler method must be overridden in subclass.')

    @classmethod
    def run(cls, log: LogHandler_T, *, always_on: bool = False) -> None:
        '''associating subclass Log reference with Listener class.

        registering all interfaces in _intfs and starting service listener loop.
        calling class method setup before to provide subclass specific code to run at class level before continuing.
        '''
        cls._log = log

        log.informational(f'{cls.__name__} initialization started.')
        # ======================
        # INITIALIZING LISTENER
        # ======================
        listener = cls()
        listener._setup()

        log.notice(f'{cls.__class__.__name__} initialization complete.')

        # starting a registration thread for all available interfaces and exit when complete
        for intf in cls._intfs:
            Thread(target=listener.__register, args=(intf,)).start()

        # running main epoll/ socket loop.
        listener.__run_listener(always_on)

    @classmethod
    def enable(cls, sock_fd: int, intf: str) -> None:
        '''adds a file descriptor id to the disabled interface set.

        this effectively re-enables the server for the zone of the specified socket.
        '''
        cls.enabled_intfs.add(sock_fd)

        cls._log.notice(f'[{sock_fd}][{intf}] {cls.__name__} listener enabled.')

    @classmethod
    def disable(cls, sock_fd: int, intf: str) -> None:
        '''removes a file descriptor id to the disabled interface set.

        this effectively disables the server for the zone of the specified socket.
        '''
        # try block is to prevent key errors on initialization. after that, key errors should not be happening.
        try:
            cls.enabled_intfs.remove(sock_fd)
        except KeyError:
            return

        cls._log.notice(f'[{sock_fd}][{intf}] {cls.__name__} listener disabled.')


class ProtoRelay:
    '''parent class for udp and tls relays.

    provides standard built in methods to start, check status, or add jobs to the work queue.
    _dns_queue object must be overwritten by subclasses.
    '''
    _protocol: ClassVar[PROTO] = PROTO.NOT_SET
    _relay_conn: RELAY_CONN

    __slots__ = (
        '_dns_server', '_fallback_relay',

        '_send_count', '_last_rcvd',
        '_responder_add', '_fallback_relay_add'
    )

    def __init__(self, dns_server: DNSServer_T, fallback_relay: Optional[Callable]):
        '''general constructor.

        May be expanded.
        '''
        self._dns_server: DNSServer_T = dns_server
        self._fallback_relay: Optional[Callable] = fallback_relay

        self._send_count: int = 0
        self._last_rcvd:  int = 0

        # direct reference for performance
        if (fallback_relay):
            self._fallback_relay_add = fallback_relay.add

    @classmethod
    def run(cls, dns_server: DNSServer_T, *, fallback_relay: Optional[Callable] = None):
        '''starts the protocol relay.

        DNSServer object is the class handling client side requests which we can call back to and fallback is a
        secondary relay that can get forwarded a request post failure. initialize will be called to run any subclass
        specific processing then query handler will run indefinitely.
        '''
        self = cls(dns_server, fallback_relay)

        Thread(target=self._fail_detection).start()
        Thread(target=self.relay).start()

    def relay(self):
        '''the main relay process for handling the relay queue. will block and run forever.
        '''
        raise NotImplementedError('relay must be implemented in the subclass.')

    def _send_query(self, request: DNS_SEND) -> int:
        for attempt in ATTEMPTS:
            try:
                nbytes = self._relay_conn.send(request.data)
            except OSError:
                nbytes = 0

            # failed to send on first try will trigger a connection reconnect and resend
            if (not nbytes and attempt != LAST_ATTEMPT):
                registered = self._register_new_socket()
                if (not registered):
                    break

            # SUCCESSFUL SEND
            elif (nbytes):
                self._send_count += 1

                return attempt

        # COMPLETE SEND FAIL
        return -1

    def _recv_handler(self):
        '''called in a thread after creating a new socket to handle all responses from remote server.
        '''
        raise NotImplementedError('_recv_handler must be implemented in the subclass.')

    def _register_new_socket(self):
        '''logic to create a socket object used for external dns queries.
        '''
        raise NotImplementedError('_register_new_socket must be implemented in the subclass.')

    @looper(FIVE_SEC)
    def _fail_detection(self):
        if (fast_time() - self._last_rcvd >= FIVE_SEC and self._send_count >= HEARTBEAT_FAIL_LIMIT):
            self.mark_server_down()

    # processes that were unable to connect/ create a socket will send in the remote server ip that was attempted.
    # if a remote server isn't specified, the active relay socket connection's remote ip will be used.
    def mark_server_down(self, *, remote_server: str = None):
        if (not remote_server):
            remote_server = self._relay_conn.remote_ip

        # the more likely case is primary server going down, so will use as baseline condition
        primary = self._dns_server.public_resolvers.primary

        # if servers could change during runtime, this has a slight race condition potential, but it shouldn't matter
        # because, when changing a server, it would be initially set to down (essentially a no-op)
        server = primary if primary['ip_address'] == remote_server else self._dns_server.public_resolvers.secondary
        server[PROTO.DNS_TLS] = False

        try:
            self._relay_conn.sock.close()
        except OSError:
            console_log(f'[{self._relay_conn.remote_ip}] Failed to close socket while marking server down.')

    @property
    def is_enabled(self) -> bool:
        '''set as true if the running class protocol matches the currently configured protocol.
        '''
        return self._dns_server.protocol is self._protocol

    @property
    def fail_condition(self) -> bool:
        '''property to streamline fallback action if condition is met.

        May be overridden and will always return False if not.
        '''
        return False


class NFQueue:
    _log: ClassVar[LogHandler_T]

    _packet_parser:  ClassVar[ProxyParser]
    _proxy_callback: ClassVar[ProxyCallback]

    DEFAULT_THREAD_COUNT = 4

    __slots__ = (
        'inspection_queue',
    )

    def __init__(self):
        self.inspection_queue = inspection_queue()

    @classmethod
    def run(cls, log: LogHandler_T, *, q_num: int) -> None:

        cls._log = log

        log.informational(f'{cls.__class__.__name__} initialization started.')
        nfqueue = cls()
        nfqueue._setup()
        log.notice(f'{cls.__class__.__name__} initialization complete.')

        nfqueue.__run_queue(q_num)

    def _setup(self):
        '''called prior to creating listener interface instances.

        May be overridden.
        '''
        pass

    # @classmethod
    # def set_proxy_callback(cls, *, func: ProxyCallback) -> None:
    #     '''Takes a callback function to handle packets after parsing.
    #
    #     the reference will be called as part of the packet flow with one argument passed in for "packet".
    #     '''
    #     if (not callable(func)):
    #         raise TypeError('Proxy callback must be a callable object.')
    #
    #     cls._proxy_callback = func

    def __run_queue(self, q: int, /) -> NoReturn:

        for _ in RUN_FOREVER:
            # on failure, we will reinitialize the extension to start fresh
            nfqueue = NetfilterQueue()

            nfqueue.nf_set(q)
            nfqueue.set_proxy_callback(self.__handle_packet)

            self._log.notice('Starting dnx_netfilter queue. Packets will be processed shortly')

            # ==============
            # BLOCKING CALL
            # ==============
            # this is a blocking call that interacts with the system via callback.
            try:
                nfqueue.nf_run()
            except:
                nfqueue.nf_break()

                self._log.alert('Netfilter binding lost.')

            fast_sleep(1)

    def __handle_packet(self, nfqueue: CPacket, mark: int) -> None:
        '''NFQUEUE callback where each call to the proxy callback is done sequentially.
        '''
        try:
            packet: ProxyPackets = self._packet_parser(nfqueue, mark)
        except ProtocolError:
            nfqueue.drop()

        except Exception as E:
            nfqueue.drop()

            self._log.error(f'Failed to parse CPacket. Packet discarded. > {E}')

        else:
            self.inspection_queue.add(packet)


# TODO: see if we can decommission this class to be replaced by CPacket.
#  this became an option after reworking dnx_nfqueue lib since the parsing and GIL operations are much more refined.
class NFPacket:
    '''base class for security module packet containers.

    instances of this class are created by calling __new__ directly via the alternate constructor "netfilter_recv".
    '''
    # C Callbacks
    nfqueue: CPacket

    # MARK FIELD's
    mark: int

    action:    DECISION
    direction: DIRECTION

    tracked_geo: int
    ipp_profile: int
    dns_profile: int
    ips_profile: int

    # HW FIELDS
    in_intf:   int
    out_intf:  int
    src_mac:   str
    timestamp: int

    # IP FIELDS
    protocol: PROTO
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int

    # TCP FIELDS
    seq_number: int
    ack_number: int

    # UDP FIELDS
    ip_header:   ByteString
    udp_header:  ByteString
    udp_payload: ByteString

    # ICMP FIELDS
    icmp_type: ICMP

    __slots__ = (
        'nfqueue', 'mark',

        'action', 'direction', 'tracked_geo',
        'ipp_profile', 'dns_profile', 'ips_profile',

        'in_intf', 'out_intf',
        'src_mac', 'timestamp',

        # ip header
        'ip_header', 'protocol',
        'src_ip', 'dst_ip',

        # proto headers
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
        '''Cython > Python attribute conversion.
        '''
        self = object.__new__(cls)

        # reference to allow higher level modules to call packet actions directly
        self.nfqueue = cpacket

        # creating instance attr so it can be modified if needed
        self.mark = mark
        # X (4b) | ips (4b) | dns (4b) | ipp (4b) | X (4b) | geo loc (8b) | direction (2b) | action (2b)
        self.action    = DECISION(mark & 3)
        self.direction = DIRECTION(mark >> 2 & 3)

        self.tracked_geo = mark >>  4 & 255
        self.ipp_profile = mark >> 16 & 15
        self.dns_profile = mark >> 20 & 15
        self.ips_profile = mark >> 24 & 15

        hw_info = cpacket.get_hw()
        self.in_intf   = hw_info[0]
        self.out_intf  = hw_info[1]
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

            # ip/udp headers are only needed for icmp response payloads [at this time]
            # packing into bytes to make icmp response generation more streamlined if needed
            self.ip_header  = bytearray(20)
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


# ==========================
# PROXY RESPONSE BASE CLASS
# ==========================
# pre-defined fields which are functionally constants for the purpose of connection resets
ip_header_template: Structure_T = PR_IP_HDR(
    (('ver_ihl', 69), ('tos', 0), ('ident', 0), ('flags_fro', 16384), ('ttl', 255), ('checksum',0))
)
tcp_header_template: Structure_T = PR_TCP_HDR(
    (('seq_num', 696969), ('offset_control', 20500), ('window', 0), ('urg_ptr', 0))
)
pseudo_header_template: Structure_T = PR_TCP_PSEUDO_HDR(
    (('reserved', 0), ('protocol', 6), ('tcp_len', 20))
)
icmp_header_template: Structure_T = PR_ICMP_HDR(
    (('type', 3), ('code', 3), ('unused', 0))
)

class RawResponse:
    '''base class for managing raw socket operations for sending data only.

    interfaces will be registered on startup to associate interface, zone, mac, ip, and active socket.
    '''
    __setup: ClassVar[bool] = False

    # dynamically provide interfaces. default returns built-ins.
    _intfs: IntfList = load_interfaces()

    _log: LogHandler_T = None
    _open_ports: ClassVar[dict[PROTO, dict[int, int]]] = {PROTO.TCP: {}, PROTO.UDP: {}}

    _registered_socks: dict[int, NFQ_SEND_SOCK] = {}
    _registered_socks_get = _registered_socks.get

    __slots__ = ()

    @classmethod
    def setup(cls, log: LogHandler_T, open_ports: dict[PROTO, dict[int, int]] = None) -> None:
        '''register all available interfaces in a separate thread for each.

        registration will wait for the interface to become available before finalizing.
        '''
        if (cls.__setup):
            raise RuntimeError('response handler setup can only be called once per process.')

        cls.__setup = True
        cls._log = log

        # direct assignment for perf
        if (open_ports):
            cls._open_ports = open_ports

        for intf in cls._intfs:
            Thread(target=cls.__register, args=(intf,)).start()

    @classmethod
    def __register(cls, intf: Intf):
        '''will register interface with ip and socket. a new socket will be used every time this method is called.
        '''
        intf_index, _intf, zone = intf

        wait_for_interface(interface=_intf)
        ip = wait_for_ip(interface=_intf)

        # sock sender is the direct reference to the socket send/to method, adding zone into value for easier
        # reference in prepare_and_send method.
        cls._registered_socks[intf_index] = NFQ_SEND_SOCK(zone, ip, cls.sock_sender())

        cls._log.informational(f'{cls.__name__}: {_intf} registered.')

    @classmethod
    def prepare_and_send(cls, packet: ProxyPackets) -> None:
        '''obtain a socket object based on the interface/zone received then prepares a raw packet (all layers).
        the internal _send method will be called once finished.

        Do not override.
        '''
        # in_intf is the interface index
        # zone is the zone id, eg 10,11,12
        intf: NFQ_SEND_SOCK = cls._registered_socks_get(packet.in_intf)

        # TODO: skip masquerade when WAN int is statically assigned
        #   why do we need to masquerade here??? wouldnt the initial dst ip be the current wan interface ip all the same?
        dnx_src_ip = packet.dst_ip if intf.zone != WAN_IN else get_masquerade_ip(dst_ip=packet.src_ip)

        # checking if dst port is associated with a nat.
        # if so, will override necessary fields based on protocol and re-assign in the packet object.
        # the chained if statement is for the more likely case of open port not being present.
        open_ports: dict = cls._open_ports[packet.protocol]
        if (open_ports):
            port_override: int = open_ports.get(packet.dst_port)
            if (port_override):
                cls._packet_override(packet, dnx_src_ip, port_override)

        # calling hook for packet generation. this can be overloaded by subclass.
        send_data: bytearray = cls._prepare_packet(packet, dnx_src_ip)
        try:
            intf.sock_sendto(send_data, (itoip(packet.src_ip), 0))
        except OSError:
            pass

    @staticmethod
    def _prepare_packet(packet: ProxyPackets, dnx_src_ip: int) -> bytearray:

        # TCP HEADER
        if (packet.protocol is PROTO.TCP):
            response_protocol = PROTO.TCP
            proto_len = 20

            # new instance of header byte container template
            protohdr = tcp_header_template()

            # assigning missing fields
            protohdr.dst_port = packet.dst_port
            protohdr.src_port = packet.src_port
            protohdr.ack_num  = packet.seq_number + 1

            proto_header = protohdr.assemble()

            # __call__ for updating fields, then assemble buffer
            psdohdr = pseudo_header_template((('src_ip', dnx_src_ip), ('dst_ip', packet.src_ip)))
            pseudo_header = psdohdr.assemble()

            # defined for final assembly simplicity
            proto_payload = b''

            # calculating checksum of container
            proto_header[16:18] = calc_checksum(pseudo_header + proto_header)

        # ICMP HEADER
        # elif (packet.protocol is PROTO.UDP):
        else:
            response_protocol = PROTO.ICMP
            proto_len = 8 + 28

            # new instance of header byte container template
            protohdr = icmp_header_template()
            proto_header = protohdr.assemble()

            # per icmp, ip header and first 8 bytes of rcvd payload are included in icmp response payload
            proto_payload = packet.ip_header + packet.udp_header

            proto_header[2:4] = calc_checksum(proto_header + proto_payload)

        # IP HEADER
        iphdr = ip_header_template()

        iphdr.tl = 20 + proto_len
        iphdr.protocol = response_protocol
        iphdr.src_ip = dnx_src_ip
        iphdr.dst_ip = packet.src_ip

        ip_header = iphdr.assemble()
        ip_header[10:12] = calc_checksum(ip_header)

        # ASSEMBLY
        return ip_header + proto_header + proto_payload

    @staticmethod
    def _packet_override(packet: ProxyPackets, dnx_src_ip: int, port_override: int):
        if (packet.protocol is PROTO.TCP):
            packet.dst_port = port_override

        # in byte form since they are included in icmp payload in raw form
        elif (packet.protocol is PROTO.UDP):
            packet.udp_header[2:4] = short_pack(port_override)

            # NOTE: did we skip udp checksum because it's not required?? prob should do it to be "legit"... someday

            # slicing operations will change the referenced object directly
            ip_header = packet.ip_header

            ip_header[10:12] = b'\x00\x00'
            ip_header[12:16] = long_pack(packet.src_ip)
            ip_header[16:20] = long_pack(dnx_src_ip)

            ip_header[10:12] = calc_checksum(ip_header)

    @staticmethod
    def sock_sender():
        '''return a new socket object to be used with interface registration.

        May be overridden.
        '''
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        return sock.sendto
