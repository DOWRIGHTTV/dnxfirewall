#!/usr/bin/python3

import os, sys
import time
import traceback
import threading
import socket
import select

from ipaddress import IPv4Address
from collections import deque

_HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, _HOME_DIR)

from netfilter.netfilterqueue import NetfilterQueue # pylint: disable=no-name-in-module, import-error

import dnx_iptools.dnx_interface as interface

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_structs import * # pylint: disable=unused-wildcard-import
from dnx_configure.dnx_namedtuples import RELAY_CONN, NFQ_SOCK, L_SOCK
from dnx_iptools.dnx_protocol_tools import checksum_ipv4, checksum_tcp, checksum_icmp
from dnx_iptools.dnx_standard_tools import looper, DNXQueue

__all__ = (
    'Listener', 'ProtoRelay', 'NFQueue', 'RawPacket', 'RawResponse'
)

def _NOT_IMPLEMENTED(*args, **kwargs):
    raise NotImplementedError('subclass must reference a data handling function.')


class Listener:
    _Log = None
    _packet_parser  = _NOT_IMPLEMENTED
    _proxy_callback = _NOT_IMPLEMENTED
    _intfs = (
        interface.get_intf('lan'),
        # interface.get_intf('dmz')
    )

    __slots__ = (
        # standard vars
        '_intf', '_intf_ip', '_threaded', '_name',

        # private vars
        '__epoll', '__registered_socks',
        '__epoll_poll', '__registered_socks_get'
    )

    def __new__(cls, *args, **kwargs):
        if (cls is Listener):
            raise TypeError('Listener can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self, intf, threaded):
        '''general constructor. can only be reached through subclass.

        May be expanded.

        '''
        self._intf = intf
        self._threaded = threaded

        self._name = self.__class__.__name__

        if (self.is_service_loop):
            self.__epoll = select.epoll()
            self.__registered_socks = {}

            # assigning local reference to method itself to prevent lookups
            self.__epoll_poll = self.__epoll.poll
            self.__registered_socks_get = self.__registered_socks.get

    def __str__(self):
        return f'Listener/{self._name}(intf={self._intf})'

    @classmethod
    def run(cls, Log, *, threaded=True):
        '''associating subclass Log reference with Listener class. registering all interfaces in _intfs and starting service listener loop. calling class method setup before to
        provide subclass specific code to run at class level before continueing.'''
        Log.notice(f'{cls.__name__} initialization started.')
        # class setup
        cls._Log = Log
        cls._setup()

        # running main epoll/ socket loop. threaded so proxy and server can run side by side
        listener = cls(None, threaded)
        threading.Thread(target=listener.__listener).start()
        # starting a registration thread for all available interfaces
        # upon registration the threads will exit
        for intf in cls._intfs:
            self = cls(intf, threaded)
            threading.Thread(target=self.__register, args=(listener,)).start()

    @classmethod
    def _setup(cls):
        '''called prior to creating listener interface instances. module wide code can be ran here.

        May be overriden.

        '''
        pass

    # TODO: what happens if interface comes online, then immediately gets unplugged. the registration would fail potentially,
    # and would no longer be active so it would never happen if the interface was replugged after.
    def __register(self, listener, intf=None):
        '''will register interface with listener. requires subclass property for listener_sock returning valid socket object.
        once registration is complete the thread will exit.'''
        # this is being defined here the listener will be able to correlate socket back to interface and send in.
        _intf = intf if intf else self._intf
        self._Log.debug(f'{self._name} started interface registration for {_intf}')

        interface.wait_for_interface(interface=_intf)
        self._intf_ip = interface.wait_for_ip(interface=_intf)

        l_sock = self.listener_sock
        listener.__registered_socks[l_sock.fileno()] = L_SOCK(l_sock, _intf) # TODO: make a namedtuple
        # TODO: if we dont re register, and im pretty sure i got rid of that, we shouldnt need to track the interface
        # anymore yea? the fd and socket object is all we need, unless we need to get the source ip address. OH. does the
        # dns proxy need to grab its interface ip for sending to the client? i dont think so, right? it jsut needs to
        # spoof the original destination.
        listener.__epoll.register(l_sock.fileno(), select.EPOLLIN)

        self._Log.notice(f'{self._name} | {_intf} registered.')

    @classmethod
    def set_proxy_callback(cls, *, func):
        '''takes a callback function to handle packets after parsing. the reference will be called
        as part of the packet flow with one argument passed in for "packet".'''
        if (not callable(func)):
            raise TypeError('proxy callback must be a callable object.')

        cls._proxy_callback = func

    @looper(NO_DELAY)
    def __listener(self):
        l_socks = self.__epoll_poll()
        for fd, _ in l_socks:
            sock_info = self.__registered_socks_get(fd)

            try:
                data, address = sock_info.socket.recvfrom(4096)
            except OSError:
                pass
            else:
                self.__parse_packet(data, address, sock_info)

    def __parse_packet(self, data, address, sock_info):
        packet = self._packet_parser(data, address, sock_info)
        try:
            packet.parse()
        except:
            traceback.print_exc()
        else:
            self.__after_parse(packet)

    def __after_parse(self, packet):
        if (self._pre_inspect(packet)):
            if (self._threaded):
                threading.Thread(target=self._proxy_callback, args=(packet,)).start()
            else:
                self._proxy_callback(packet)

    def _pre_inspect(self, packet):
        '''handle the request after packet is parsed and confirmed protocol match.

        Must be overriden.

        '''
        pass

    @property
    def listener_sock(self):
        '''returns instance level listener socket.

        Must be overridden.

        '''
        raise NotImplementedError('the listenr sock property must be overriden in subclass.')

    @property
    def is_service_loop(self):
        '''boolean value representing whether current instance is a listener.'''
        return self._intf is None

    @classmethod
    def send_to_client(cls, packet):
        '''sending data generated by server over socket original data was recieved on.

        May be overridden.

        '''
        try:
            packet.sock.send(packet.send_data)
        except OSError:
            pass # NOTE: make this nicer, this is incase socket gets shutdown midway


# TODO: test the new fail detection algo stuffs and ensure it is working as inteded or whatever ya know.
class ProtoRelay:
    '''parent class for udp and tls relays providing standard built in methods to start, check status, or add
    jobs to the work queue. _dns_queue object must be overwritten by sub classes.'''
    _protocol  = PROTO.NOT_SET

    __slots__ = (
        # callbacks
        'DNSServer', '_fallback',

        # protected vars
        '_relay_conn', '_send_cnt', '_last_sent'
    )

    def __new__(cls, *args, **kwargs):
        if (cls is ProtoRelay):
            raise TypeError('Listener can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self, DNSServer, fallback):
        '''general constructor. can only be reached through subclass.

        May be expanded.

        '''
        self.DNSServer = DNSServer
        self._fallback = fallback
        self._relay_conn = RELAY_CONN(None, socket.socket())

        self._send_cnt  = 0
        self._last_sent = 0

    @classmethod
    def run(cls, DNSServer, *, fallback=None):
        '''starts the protocol relay. DNSServer object is the class handling client side requests which
        we can call back to and fallback is a secondary relay that can get forwarded a request post failure.
        initialize will be called to run any subclass specific processing then query handler will run indefinately.'''
        self = cls(DNSServer, fallback)

        threading.Thread(target=self._fail_detection).start()
        threading.Thread(target=self.relay).start()

    def relay(self):
        '''main relay process for handling the relay queue. will block and run forever.'''

        raise NotImplementedError('relay must be implemented in the subclass.')

    def _send_query(self, client_query):
        for attempt in range(2):
            try:
                self._relay_conn.sock.send(client_query.send_data)
            except OSError:
                if not self._register_new_socket(): break

                threading.Thread(target=self._recv_handler).start()
            else:
                self._increment_fail_detection()
                if (self._protocol is PROTO.DNS_TLS):
                    print(f'SENT {self._relay_conn.sock.version()}[{attempt}]: {client_query.request}')
                else:
                    print(f'SENT {self._protocol.name}[{attempt}]: {client_query.request}') # pylint: disable=no-member
                break

    def _recv_handler(self):
        '''called in a thread after creating new socket to handle all responses from remote server.'''

        raise NotImplementedError('_recv_handler method must be overridden in subclass.')

    def _register_new_socket(self):
        '''logic to create socket object used for external dns queries.'''

        raise NotImplementedError('_register_new_socket method must be overridden in subclass.')

    @looper(FIVE_SEC)
    def _fail_detection(self):
        if (time.time() - self._last_sent >= FIVE_SEC
                and self._send_cnt >= HEARTBEAT_FAIL_LIMIT):
            self.mark_server_down()

    # aquires lock then will mark server down if it is present in config
    def mark_server_down(self):
        self._relay_conn.sock.close()
        with self.DNSServer.server_lock:
            for server in self.DNSServer.dns_servers:
                if (server['ip'] == self._relay_conn.remote_ip):
                    self.DNSServer.dns_servers[server['ip']][self._protocol] = False

    def _send_to_fallback(self, client_query):
        '''allows for relay to fallback to a secondary relay. uses class object passed into run method.'''
        self._fallback.relay.add(client_query)

    def _reset_fail_detection(self):
        self._send_cnt = 0

    def _increment_fail_detection(self):
        self._send_cnt += 1
        self._last_sent = time.time()

    @property
    def is_enabled(self):
        '''set as true if the running classes protocol matches the currently configured protocol.'''
        return self.DNSServer.protocol is self._protocol

    @property
    def socket_available(self):
        '''returns true if current relay socket object has not been closed.'''
        return self._relay_conn.sock.fileno() != -1

    @property
    def standby_condition(self):
        '''property to reduce length of delay in queue handler.

        May be overridden.

        '''
        return False

    @property
    def fail_condition(self):
        '''property to streamline fallback action if condition is met. returns False by default.

        May be overridden.

        '''
        return False

    @staticmethod
    def is_keepalive(data):
        return short_unpackf(data)[0] == DNS.KEEPALIVE


# TODO: deal with log reference
class NFQueue:
    _Log = None
    _packet_parser  = _NOT_IMPLEMENTED
    _proxy_callback = _NOT_IMPLEMENTED
    _intfs = []

    __slots__ = (
        # private vars
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
    def run(cls, Log, *, q_num, threaded=False):
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
        '''takes a callback function to handle packets after parsing. the reference will be called
        as part of the packet flow with one argument passed in for "packet".'''
        if (not callable(func)):
            raise TypeError('proxy callback must be a callable object.')

        cls._proxy_callback = func

    def __queue(self):
        self._Log.notice('Starting netfilter queue. Packets can now be processed')
        nfqueue = NetfilterQueue()
        nfqueue.bind(self.__q_num, self.__nfqueue_callback)
        try:
            nfqueue.run()
        except Exception:
            self._Log.warning('Netfilter Queue error. Unbinding from queue and attempting to rebind.')
            nfqueue.unbind()

        # TODO: remove the recursive call if possible maybe use threading even to wait for
        # something to happen before calling.
        time.sleep(1)
        self.__queue()

    def __nfqueue_callback(self, nfqueue):
        if self._pre_check(nfqueue):
            self._parse_packet(nfqueue)

    def __after_parse(self, packet):
        if self._pre_inspect(packet):
            if (self.__threaded):
                threading.Thread(target=self._proxy_callback, args=(packet,)).start()
            else:
                self._proxy_callback(packet)

    def _pre_check(self, nfqueue):
        '''allowing code to be executed before parsing. return will be checked as a boolean where
        True will continue and False will return.

        May be overridden.

        '''
        return True

    def _parse_packet(self, nfqueue):
        packet = self._packet_parser(nfqueue)
        try:
            packet.parse()
        except Exception:
            traceback.print_exc()
        else:
            self.__after_parse(packet)

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


class RawPacket:
    '''parent class designed to index/parse full tcp/ip packets (including ethernet). two alternate
    constructors are supplied to support nfqueue or raw sockets.

    raw socket:
        packet = RawPacket.interface(data, address, socket)

    nfqueue:
        packet = RawPacket.netfilter(nfqueue)

    the before_exit method can be overridden to extend the parsing functionality, for example to group
    objects in namedtuples or to index application data.

    '''
    __slots__ = (
        # protected vars
        '_data', '_dlen', '_addr', '_intf',
        # public vars - init
        'timestamp', 'protocol',
        'nfqueue', 'sock', 'zone',
        'src_mac', 'dst_mac',
        'sf_octet', 'df_octet',
        'src_ip', 'dst_ip', 'ip_header',
        'src_port', 'dst_port',

        # public vars - tcp
        'seq_number', 'ack_number',

        # udp
        'udp_len', 'udp_chk',
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
        self.timestamp = time.time()
        self.protocol  = PROTO.NOT_SET

    def __str__(self):
        return f'{self.__class__.__name__}(proto={self.protocol}, len={self._dlen})'

    @classmethod
    def netfilter(cls, nfqueue):
        '''alternate constructor. used to start listener/proxy instances using nfqueue bindings.'''
        self = cls()
        self.nfqueue = nfqueue
        self._data   = nfqueue.get_payload()
        self.zone    = nfqueue.get_mark()
        self.src_mac = nfqueue.get_hw()
        if (self.src_mac):
            self.src_mac = self.src_mac[:6]
        self._dlen = len(self._data)

        return self

    @classmethod
    def interface(cls, data, address, sock_info):
        '''alternate constructor. used to start listener/proxy instances bound to physical interfaces(active socket).'''
        self = cls()
        self._data = data
        self._addr = address
        self.sock, self._intf = sock_info

        self._dlen = len(self._data)

        self.dst_mac = data[:6]
        self.src_mac = data[6:12]
        self._data   = data[14:]

        return self

    def parse(self):
        '''index tcp/ip packet layers 3 & 4 for use as instance objects.

        the before_exit method will be called before returning. this can be used to create
        subclass specific objects like namedtuples or application layer data.'''
        self.__ip()
        if (self.protocol == PROTO.TCP):
            self.__tcp()
        elif (self.protocol == PROTO.UDP):
            self.__udp()
        elif (self.protocol == PROTO.ICMP):
            self.__icmp()

        if (self.continue_condition):
            self._before_exit()

    def __ip(self):
        data = self._data
        self.sf_octet = data[12]
        self.df_octet = data[16]
        self.src_ip = IPv4Address(data[12:16])
        self.dst_ip = IPv4Address(data[16:20])

        header_len = (data[0] & 15) * 4
        self.protocol  = data[9]
        self.ip_header = data[:header_len]

        # removing ip header from data
        self._data = data[header_len:]

    # tcp header max len 32 bytes
    def __tcp(self):
        tcp_header = tcp_header_unpack(self._data)
        self.src_port   = tcp_header[0]
        self.dst_port   = tcp_header[1]
        self.seq_number = tcp_header[2]
        self.ack_number = tcp_header[3]

    # udp header 8 bytes
    def __udp(self):
        udp_header = udp_header_unpack(self._data)
        self.src_port = udp_header[0]
        self.dst_port = udp_header[1]
        self.udp_len  = udp_header[2]
        self.udp_chk  = udp_header[3]

        self.udp_header  = self._data[:8]
        self.udp_payload = self._data[8:self.udp_len]

    def __icmp(self):
        self.icmp_type = self._data[0]

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


# TODO: handle log reference situation
class RawResponse:
    '''base class for managing raw socket operations for sending only. interfaces will be registered
    on startup to associate interface, zone, mac, ip, and active socket. the registration process will
    restart on an individual interface basis if a socket error occurs.'''
    __setup = False
    _Log = None
    _Module = None
    _registered_socks = {}
    _intfs  = (
        (LAN_IN, interface.get_intf('lan')),
        (WAN_IN, interface.get_intf('wan')),
#        (DMZ_IN, interface.get_intf('dmz'))
    )

    __slots__ = (
        '_intf', '_packet',
        '_dnx_src_mac', '_dnx_src_ip',
        'send_data'
    )

    def __new__(cls, *args, **kwargs):
        if (cls is RawResponse):
            raise TypeError('RawResponse can only be used via inheritance.')

        return object.__new__(cls)


    @classmethod
    def setup(cls, Module, Log):
        '''iterating over available interfaces, creating a new class instance, then calling
        internal register method in a new thread.'''
        if (cls.__setup):
            raise RuntimeError('response handler setup can only be called once per process.')
        cls.__setup = True

        cls._Module = Module
        cls._Log = Log
        for intf in cls._intfs:
            self = cls()
            threading.Thread(target=self.__register, args=(intf,)).start()

    def __register(self, intf):
        '''will register interface with ip and socket. a new socket will be used every
        time this method is called.

        Do not override.

        '''
        zone, _intf = intf
        self._intf  = _intf

        interface.wait_for_interface(interface=_intf)
        ip  = interface.wait_for_ip(interface=_intf)
        mac = interface.get_mac(interface=_intf)

        self._registered_socks[zone] = NFQ_SOCK(*intf, mac, ip, self.listener_sock)

        self._Log.notice(f'{self.__class__.__name__}: {_intf} registered.')

    @classmethod
    def prepare_and_send(cls, packet):
        '''obtains socket object based on interface/zone receieved then prepares a raw packet (all layers).
        internal _send method will be called once finished.

        Do not override.

        '''
        zone = packet.zone

        self = cls()
        self._packet = packet
        # self._zone   = packet.zone

        self._intf = self._registered_socks.get(zone)
        self._dnx_src_mac = self._intf.mac
        self._dnx_src_ip  = packet.dst_ip.packed

        #NOTE: if interface call fails, it will return none from raised exception.
        # see if this is ok, if we should pack after checking return, or return quads 0s.
        if (zone == WAN_IN): # TODO: if static assigned dont need, make a condition.
            self._dnx_src_ip = interface.get_src_ip(dst_ip=packet.src_ip).packed

        if (self._override_needed(packet)):
            self._packet_override(packet)

        self._prepare_packet(packet)

        self.__send()

    def _prepare_packet(self, packet):
        '''generates send data based on received packet data and interface/zone.

        Must be overriden.

        '''
        self.send_data = b''

    def _packet_override(self, packet):
        '''overrides protocol information to reverse pre route nat changes.

        May be overridden.

        '''
        pass

    def __send(self):
        '''sends generated data over obtained socket from prepare and send method. !MAYBE: if an error occurs
        a new interface registration thread will be called, but packet will be lost.

        Do not override.

        '''
        try:
            self._intf.sock.send(self.send_data)
        except OSError:
            pass

    def _override_needed(self, packet):
        '''property representing packet override condition, if this returns True the override method
        will be called from prepare and send. default is False.

        May be overriden.

        '''
        return False

    @property
    def listener_sock(self):
        '''returns new socket object to be used with interface registration.

        May be overriden.

        '''
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((self._intf, 3))

        return sock
