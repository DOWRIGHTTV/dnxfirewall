#!/usr/bin/env python3

import os, sys
import time
import traceback
import threading
import socket
import select

from ipaddress import IPv4Address

_HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-3]))
sys.path.insert(0, _HOME_DIR)

from dnx_gentools.def_constants import *
from dnx_iptools.def_structs import *

from dnx_gentools.def_namedtuples import RELAY_CONN, NFQ_SEND_SOCK, L_SOCK

from dnx_netmods.dnx_netfilter.dnx_nfqueue import set_user_callback, NetfilterQueue # pylint: disable=no-name-in-module, import-error
from dnx_iptools.interface_ops import load_interfaces, wait_for_interface, wait_for_ip, get_masquerade_ip
from dnx_iptools.protocol_tools import int_to_ipaddr
from dnx_gentools.standard_tools import looper


__all__ = (
    'Listener', 'ProtoRelay', 'NFQueue', 'NFPacket', 'RawPacket', 'RawResponse'
)

def _NOT_IMPLEMENTED(*args, **kwargs):
    raise NotImplementedError('subclass must reference a data handling function.')


class Listener:
    _Log = None
    _packet_parser  = _NOT_IMPLEMENTED
    _proxy_callback = _NOT_IMPLEMENTED

    _intfs = load_interfaces(exclude=['wan'])

    # stored as file descriptors to minimize lookups in listener queue.
    enabled_intfs = set()

    __slots__ = (
        '_intf', '_intf_ip',
        '_threaded', '_always_on', '_name',

        '__epoll_poll', '__registered_socks_get'
    )

    def __new__(cls, *args, **kwargs):
        if (cls is Listener):
            raise TypeError('Listener can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self, threaded, always_on):
        '''general constructor. can only be reached through subclass.

        May be expanded.

        '''
        self._threaded = threaded
        self._always_on = always_on

    @classmethod
    def run(cls, Log, *, threaded=True, always_on=False):
        '''associating subclass Log reference with Listener class. registering all interfaces in _intfs and starting
        service listener loop. calling class method setup before to provide subclass specific code to run at class level
        before continuing.'''

        Log.informational(f'{cls.__name__} initialization started.')

        cls._Log = Log
        cls.__registered_socks = {}
        cls.__epoll = select.epoll()

        # child class hook to initialize higher level systems. NOTE: must stay after initial intf registration
        cls._setup()

        # starting a registration thread for all available interfaces
        # upon registration the threads will exit
        for intf in cls._intfs:
            threading.Thread(target=cls.__register, args=(intf,)).start()

        # running main epoll/ socket loop. threaded so proxy and server can run side by side
        # TODO: should be able to convert this into a class object like RawPacket. just need to
        #  make sure name mangling takes care of the reference issues if 2 classes inherit from
        #  this class within the same process..
        self = cls(threaded, always_on)
        threading.Thread(target=self.__listener).start()

    @classmethod
    def enable(cls, sock_fd, intf):
        '''adds a file descriptor id to the disabled interface set. this effectively re-enables the server for the
        zone of the specified socket.'''

        cls.enabled_intfs.add(sock_fd)

        cls._Log.notice(f'[{sock_fd}][{intf}] {cls.__name__} listener enabled.')

    @classmethod
    def disable(cls, sock_fd, intf):
        '''removes a file descriptor id to the disabled interface set. this effectively disables the server for the
        zone of the specified socket.'''

        # try block is to prevent key errors on initialization. after that, key errors should not be happening.
        try:
            cls.enabled_intfs.remove(sock_fd)
        except KeyError:
            pass

        cls._Log.notice(f'[{sock_fd}][{intf}] {cls.__name__} listener disabled.')

    @classmethod
    def _setup(cls):
        '''called prior to creating listener interface instances. module wide code can be run here.

        May be overridden.

        '''
        pass

    @classmethod
    # TODO: what happens if interface comes online, then immediately gets unplugged. the registration would fail
    #  potentially and would no longer be active so it would never happen if the interface was replugged after.
    def __register(cls, intf):
        '''will register interface with listener. requires subclass property for listener_sock returning valid socket
        object. once registration is complete the thread will exit.'''

        # this is being defined here so the listener will be able to correlate socket back to interface and send in.
        # NOTE: we can probably _ the first 2 vars, but they may actually come in handy for something so check to see
        # if they can be used to simplify the file descriptor tracking we had to implement awhile back.
        intf_index, zone, _intf = intf

        cls._Log.debug(f'[{_intf}] {cls.__name__} started interface registration.')

        wait_for_interface(interface=_intf)

        intf_ip = wait_for_ip(interface=_intf)

        l_sock = cls.listener_sock(_intf, intf_ip)
        cls.__registered_socks[l_sock.fileno()] = L_SOCK(_intf, intf_ip, l_sock, l_sock.send, l_sock.sendto, l_sock.recvfrom)

        # TODO: if we dont re register, and im pretty sure i got rid of that, we shouldnt need to track the interface
        #  anymore yea? the fd and socket object is all we need, unless we need to get the source ip address. OH. does
        #  the dns proxy need to grab its interface ip for sending to the client? i dont think so, right? it just needs
        #  to spoof the original destination.
        cls.__epoll.register(l_sock.fileno(), select.EPOLLIN)

        cls._Log.informational(f'[{l_sock.fileno()}][{intf}] {cls.__name__} interface registered.')

    @classmethod
    def set_proxy_callback(cls, *, func):
        '''takes a callback function to handle packets after parsing. the reference will be called
        as part of the packet flow with one argument passed in for "packet".'''

        if (not callable(func)):
            raise TypeError('proxy callback must be a callable object.')

        cls._proxy_callback = func

    def __listener(self):
        epoll_poll = self.__epoll.poll
        registered_socks_get = self.__registered_socks.get

        parse_packet = self.__parse_packet

        while True:
            l_socks = epoll_poll()
            for fd, _ in l_socks:

                sock_info = registered_socks_get(fd)
                try:
                    data, address = sock_info.recvfrom(4096)
                except OSError:
                    pass

                else:
                    # this is being used as a mechanism to disable/enable interface listeners
                    if (self._always_on or fd in self.enabled_intfs):
                        parse_packet(data, address, sock_info)

                    else:
                        self._Log.debug(f'recv on fd: {fd} | enabled ints: {self.enabled_intfs}')

    def __parse_packet(self, data, address, sock_info):
        packet = self._packet_parser(address, sock_info)
        try:
            packet.parse(data)
        except:
            traceback.print_exc()

        else:
            # referring to child class for whether to continue processing the packet
            if not self._pre_inspect(packet): return

            if (self._threaded):
                threading.Thread(target=self._proxy_callback, args=(packet,)).start()
            else:
                self._proxy_callback(packet)

    def _pre_inspect(self, packet):
        '''handle the request after packet is parsed and confirmed protocol match.

        Must be overriden.

        '''
        raise NotImplementedError('the _pre_inspect method must be overridden in subclass.')

    @staticmethod
    def send_to_client(packet):
        '''sending data generated by server over socket original data was received on.

        May be overridden.

        '''
        raise NotImplementedError('the send_to_client must be overridden in subclass.')

    @staticmethod
    def listener_sock(intf, intf_ip):
        '''returns instance level listener socket.

        Must be overridden.

        '''
        raise NotImplementedError('the listener_sock method must be overridden in subclass.')


class ProtoRelay:
    '''parent class for udp and tls relays providing standard built in methods to start, check status, or add
    jobs to the work queue. _dns_queue object must be overwritten by sub classes.'''
    _protocol  = PROTO.NOT_SET

    __slots__ = (
        '_DNSServer', '_fallback_relay',

        '_relay_conn', '_send_cnt', '_last_rcvd',
        '_responder_add', '_fallback_relay_add'
    )

    def __new__(cls, *args, **kwargs):
        if (cls is ProtoRelay):
            raise TypeError('ProtoRelay can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self, DNSServer, fallback_relay):
        '''general constructor. can only be reached through subclass.

        May be expanded.

        '''
        self._DNSServer = DNSServer
        self._fallback_relay = fallback_relay

        sock = socket.socket()
        self._relay_conn = RELAY_CONN(None, sock, sock.send, sock.recv, None)

        self._send_cnt  = 0
        self._last_rcvd = 0

        # direct reference for performance
        if (fallback_relay):
            self._fallback_relay_add = fallback_relay.add

    @classmethod
    def run(cls, DNSServer, *, fallback_relay=None):
        '''starts the protocol relay. DNSServer object is the class handling client side requests which
        we can call back to and fallback is a secondary relay that can get forwarded a request post failure.
        initialize will be called to run any subclass specific processing then query handler will run indefinitely.'''
        self = cls(DNSServer, fallback_relay)

        threading.Thread(target=self._fail_detection).start()
        threading.Thread(target=self.relay).start()

    def relay(self):
        '''main relay process for handling the relay queue. will block and run forever.'''

        raise NotImplementedError('relay must be implemented in the subclass.')

    def _send_query(self, client_query):
        for attempt in range(2):
            try:
                self._relay_conn.send(client_query.send_data)
            except OSError as ose:
                # NOTE: temporary
                console_log(f'[{self._relay_conn.remote_ip}/{self._relay_conn.version}] Send error: {ose}')

                if not self._register_new_socket(): break

                threading.Thread(target=self._recv_handler).start()

            else:
                self._increment_fail_detection()

                # NOTE: temp | identifying connection version to terminal. when removing consider having the relay
                # protocol show in the webui > system reports.
                console_log(f'[{self._relay_conn.remote_ip}/{self._relay_conn.version}][{attempt}] Sent {client_query.request}\n') # pylint: disable=no-member

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
    def mark_server_down(self, *, remote_server=None):
        if (not remote_server):
            remote_server = self._relay_conn.remote_ip

        # more likely case is primary server going down so will use as baseline condition
        primary = self._DNSServer.dns_servers.primary

        # if servers could change during runtime, this has a slight race condition potential, but it shouldn't matter
        # because when changing a server it would be initially set to down (essentially a no-op)
        server = primary if primary['ip'] == remote_server else self._DNSServer.dns_servers.secondary
        server[PROTO.DNS_TLS] = False

        try:
            self._relay_conn.sock.close()
        except OSError:
            console_log(f'[{self._relay_conn.remote_ip}] Failed to close socket while marking server down.')

    def _increment_fail_detection(self):
        self._send_cnt += 1

    @property
    def is_enabled(self):
        '''set as true if the running classes protocol matches the currently configured protocol.'''

        return self._DNSServer.protocol is self._protocol

    @property
    def fail_condition(self):
        '''property to streamline fallback action if condition is met. returns False by default.

        May be overridden.

        '''
        return False


class NFQueue:
    _Log = None
    _packet_parser  = _NOT_IMPLEMENTED
    _proxy_callback = _NOT_IMPLEMENTED

    __slots__ = (
        '__q_num', '__threaded'
    )

    def __new__(cls, *args, **kwargs):
        if (cls is NFQueue):
            raise TypeError('NFQueue can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self, q_num, threaded):
        '''Constructor. can only be reached if called through subclass.

        May be extended.

        '''
        self.__q_num = q_num
        self.__threaded = threaded

    @classmethod
    def run(cls, Log, *, q_num, threaded=True):
        cls._setup()
        cls._Log = Log

        self = cls(q_num, threaded)
        self.__queue()

    @classmethod
    def _setup(cls):
        '''called prior to creating listener interface instances. module wide code can be ran here.

        May be overriden.

        '''
        pass

    @classmethod
    def set_proxy_callback(cls, *, func):
        '''Takes a callback function to handle packets after parsing. the reference will be called
        as part of the packet flow with one argument passed in for "packet".'''

        if (not callable(func)):
            raise TypeError('Proxy callback must be a callable object.')

        cls._proxy_callback = func

    def __queue(self):
        set_user_callback(self.__handle_packet)

        while True:
            nfqueue = NetfilterQueue()
            nfqueue.nf_set(self.__q_num)

            self._Log.notice('Starting dnx_netfilter queue. Packets can now be processed')

            # this is a blocking call which interacts with system via callback. while loop is to re establish the
            # queue handle after an uncaught exception (hopefully maintaining system uptime)
            try:
                nfqueue.nf_run()
            except:
                nfqueue.nf_break()

                self._Log.alert('Netfilter binding lost. Attempting to rebind.')

            time.sleep(1)

    def __handle_packet(self, nfqueue, mark):
        try:
            packet = self._packet_parser(nfqueue, mark)
        except:
            nfqueue.drop()

            traceback.print_exc()
            self._Log.error('failed to parse CPacket. Packet discarded.')

        else:
            if self._pre_inspect(packet):
                if (self.__threaded):
                    threading.Thread(target=self._proxy_callback, args=(packet,)).start()
                else:
                    self._proxy_callback(packet)

    def _pre_inspect(self, packet):
        '''automatically called after parsing. used to determine course of action for packet. nfqueue drop, accept, or repeat can be called within
        this scope. return will be checked as a boolean where True will continue and False will do nothing.

        May be overridden.

        '''
        return True

    def _handle_request(self, packet):
        '''primary logic for dealing with packet actions. nfqueue drop, accept, or repeat should be
        called within this scope if not already called in pre inspect.

        May be overridden.

        '''
        packet.nfqueue.accept()


class NFPacket:

    __slots__ = (
        'nfqueue',

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
    def netfilter_rcv(cls, cpacket, mark):
        '''Cython > Python attribute conversion'''

        self = cls()

        # reference to allow higher level modules to call packet actions directly
        self.nfqueue = cpacket

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
            self.ip_header = ip_header_pack(*ip_header)
            self.udp_header = udp_header_pack(*proto_header)

            # data payload only used by IPS/IDS (portscan detection) [at this time]
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
    '''NOTICE: this class has been significantly reduced in use. this should probably be reduced
    in code as well or a new class should be derived from it for the dns proxy.

    parent class designed to index/parse full tcp/ip packets (including ethernet). alternate
    constructors are supplied to support different listener types eg. raw sockets.

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

        # intf_ip used to fill sinkhole query response with firewall interface ip (of intf received on)
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

            self.src_port, self.dst_ip = double_short_unpack([data[:4]])

            # tcp header max len 32 bytes
            if (self.protocol is PROTO.TCP):

                self.seq_number, self.ack_number = double_long_unpack(data[4:8])

            # udp header 8 bytes
            elif (self.protocol is PROTO.UDP):
                self.udp_len, self.udp_chk = double_short_unpack([data[4:8]])

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
    def continue_condition(self):
        '''controls whether the _before_exit method gets called. must return a boolean.

        May be overridden.

        '''
        return True


class RawResponse:
    '''base class for managing raw socket operations for sending data only. interfaces will be registered
    on startup to associate interface, zone, mac, ip, and active socket.'''

    __setup = False
    _Log = None
    _Module = None
    _registered_socks = {}

    # interface operation function to dynamically provide function. default returns builtins.
    _intfs = load_interfaces()

    __slots__ = (
        '_packet', 'send_data'
    )

    def __new__(cls, *args, **kwargs):
        if (cls is RawResponse):
            raise TypeError('RawResponse can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self, packet):
        self._packet = packet
        self.send_data = b''

    @classmethod
    def setup(cls, Log, Module):
        '''register all available interfaces in a separate thread for each. registration will wait for the interface to
        become available before finalizing.'''

        if (cls.__setup):
            raise RuntimeError('response handler setup can only be called once per process.')

        cls.__setup = True

        cls._Log = Log
        cls._Module = Module

        # direct assignment for perf
        cls._registered_socks_get = cls._registered_socks.get

        for intf in cls._intfs:
            threading.Thread(target=cls.__register, args=(intf,)).start()

    @classmethod
    def __register(cls, intf):
        '''will register interface with ip and socket. a new socket will be used every time this method is called.

        Do not override.

        '''
        intf_index, zone, _intf = intf

        wait_for_interface(interface=_intf)
        ip = wait_for_ip(interface=_intf)

        # sock sender is the direct reference to the socket send/to method, adding zone into value for easier
        # reference in prepare and send method.
        cls._registered_socks[intf_index] = NFQ_SEND_SOCK(zone, ip, cls.sock_sender(_intf))

        cls._Log.informational(f'{cls.__name__}: {_intf} registered.')

    @classmethod
    def prepare_and_send(cls, packet):
        '''obtains socket object based on interface/zone received then prepares a raw packet (all layers).
        internal _send method will be called once finished.

        Do not override.

        '''

        self = cls(packet)

        # in_zone is actually interface index, but zones are linked through this identifier
        intf = self._registered_socks_get(packet.in_zone)

        # NOTE: if the wan interface has a static ip address we can use the ip assigned during registration.
        # this will need a condition to check, but wont need to masquerade.
        dnx_src_ip = packet.dst_ip if intf.zone != WAN_IN else get_masquerade_ip(dst_ip=packet.src_ip)

        # calling hook for packet generation in subclass then sending via direct socket sendto ref
        send_data = self._prepare_packet(packet, dnx_src_ip)
        try:
            intf.sock_sendto(send_data, (int_to_ipaddr(packet.src_ip), 0))
        except OSError:
            pass

    def _prepare_packet(self, packet, dnx_src_ip):
        '''generates send data based on received packet data and interface/zone.

        Must be overridden.

        '''
        raise NotImplementedError('_prepare_packet method needs to be overridden by subclass.')

    @staticmethod
    def sock_sender(intf):
        '''returns new socket object to be used with interface registration.

        May be overridden.

        '''
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        return sock.sendto
