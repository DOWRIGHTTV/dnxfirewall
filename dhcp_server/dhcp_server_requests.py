#!/usr/bin/env python3

import os, sys
import time
import json
import threading
import random

from ipaddress import IPv4Address
from subprocess import run, CalledProcessError, DEVNULL

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_structs import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_protocol_tools import icmp_reachable
from dnx_configure.dnx_file_operations import load_configuration, ConfigurationManager
from dnx_logging.log_main import LogHandler as Log

_NULL_OPT = (0,'')
_fast_choice = random.choice

__all__ = (
    'ServerResponse', 'ClientRequest'
)


class ServerResponse:
    __slots__ = (
        '_svr', '_request', '_lease_time',
        '_intf_net', '_r_start', '_r_end',
        '_check_icmp_reach'
    )

    def __init__(self, intf=None, *, server):
        self._svr = server

        # if interface ident is sent in we will assign config values. offer/ ack require these
        # values while release does not.
        if (intf):
            _intf_settings = server.intf_settings[intf]
            self._intf_net = _intf_settings['ip'].network
            self._r_start  = _intf_settings['lease_range']['start']
            self._r_end    = _intf_settings['lease_range']['end'] + 1
            self._check_icmp_reach = _intf_settings['icmp_check']

    # if client sends a dhcp release, will ensure client info matches current lease then remove
    # lease from table
    def release(self, ip_address, mac_address):
        '''release ip address lease stored in server. listener/server instance required.'''
        _, lease_time, lease_mac = self._svr.leases[ip_address]
        if (lease_time != DHCP.RESERVATION and lease_mac == mac_address):
            return True

        return False

    def offer(self, discover):
        if (discover.reservation): return discover.reservation

        is_available, lease_mac = self.is_available(discover.req_ip, mac=True)
        # outcome 1/2 in rfc 2131
        if ((discover.ciaddr != INADDR_ANY)
                and (lease_mac == discover.mac or is_available)):
            return discover.ciaddr

        # outcome 3 in rfc 2131
        if (discover.req_ip and is_available):
            return discover.req_ip

        # outcome 4 in rfc 2131
        with self._svr.handout_lock:
            return self._get_available_ip()

    def ack(self, request):
        self._request = request
        self._lease_time, _, lease_mac = self._svr.leases[request.req_ip]

        # DHCP.SELECTING
        if (self.selecting):
            # extra validation to ensure an offer cannot be stolen by another client. rfc does not mention this.
            if (lease_mac != request.mac):
                return DHCP.DROP, None

            return DHCP.ACK, request.req_ip

        # DHCP.INIT_REBOOT
        elif (self.init_reboot):
            # client request from a different network, responding with NAK
            if (request.req_ip not in self._intf_net):
                return DHCP.NAK, None

            # client lease does not exist, remaining silent
            if (not lease_mac):
                return DHCP.DROP, None

            # client lease does not match client request, sending NAK
            elif (lease_mac != request.mac):
                return DHCP.NAK, None

            # client lease matches client, renewing lease and responsing with ip
            return DHCP.ACK, request.req_ip

        # DHCP.REBINDING or DHCP.RENEWING
        elif (self.lease_active):
            # NOTE: this is not specified in RFC 2131, look into this, should be safer and not cause problems
            # client lease does not match server held lease, remaining silent
            if (lease_mac != request.mac):
                return DHCP.DROP, None

            # Because 'giaddr' is not filled in, the DHCP server will trust the value in 'ciaddr', and
            # use it when replying to the client.
            elif (self.renewing):
                return DHCP.RENEWING, request.ciaddr

            # This message MUST be broadcast to the 0xffffffff IP broadcast address.
            elif (self.rebinding):
                return DHCP.REBINDING, request.ciaddr

    @property
    def selecting(self):
        request = self._request
        if (request.ciaddr == INADDR_ANY
                and request.server_ident and request.req_ip):
            return True

        return False

    @property
    def init_reboot(self):
        request = self._request
        if (not request.server_ident and request.req_ip):
            return True

        return False

    @property
    def lease_active(self):
        request = self._request
        if (request.ciaddr != INADDR_ANY
                and not request.server_ident and not request.req_ip):
            return True

        return False

    @property
    def rebinding(self):
        if (fast_time() - self._lease_time >= 74025):
            return True

        return False

    @property
    def renewing(self):
        if (43200 <= fast_time() - self._lease_time < 74025):
            return True

        return False

    # generate available random IP in network range. if no ip is available None will be returned.
    # If icmp reachability check is enabled, and the ip is reachable, the process will continue
    # until a valid ip is selected or loop is exhausted
    def _get_available_ip(self):
        local_net = list(self._intf_net)[self._r_start:self._r_end]
        for _ in range(len(local_net)):
            ip_address = _fast_choice(local_net)

            if not self.is_available(ip_address): continue

            if (self._check_icmp_reach): # TODO: figure out how we will get notified
                if icmp_reachable(ip_address): continue

            return ip_address
        else:
            Log.critical('IP handout error. No available IPs in range.') # TODO: comeback

    def is_available(self, ip_address, mac=False):
        '''returns True if the ip address is available to lease out. if mac is set to True a tuple of status and
        associated mac, if any, will be returned.'''
        lease_status, _, lease_mac = self._svr.leases[ip_address]

        status = True if lease_status is DHCP.AVAILABLE else False

        return status if not mac else status, lease_mac


class ClientRequest:

    _Server = None
    _pack = {
        -1: [4, dhcp_ip_pack],
        1: [1, dhcp_byte_pack],
        2: [2, dhcp_short_pack],
        4: [4, dhcp_long_pack]
    }

    __slots__ = (
        '_data', '_address', '_name', '_intf_net',
        'init_time', 'server_ident', 'mtype', 'req_ip',
        'handout_ip', 'requested_options', 'response_header',
        'response_options', 'bcast', 'xID', 'ciaddr', 'chaddr', 'mac',
        '_response_mtype', 'send_data', 'sock', 'intf',

        # local references to callbacks
        '_server_options_get', '_server_reservations',
        '_server_int_ip'
    )

    @classmethod
    def set_server_reference(cls, server_reference):
        '''setting the class object alias "_Server" as the sent in reference object. this is required as all
        methods in this class rely on the alias reference.'''

        cls._Server = server_reference

    def __init__(self, data, address, sock_info):
        # NOTE: sock_info (namedtuple): name ip socket send sendto recvfrom

        self._data = data
    #    self._address = address
        self.sock = sock_info

        self.init_time    = fast_time()
        self.server_ident = None
        self.mtype        = None
        self.req_ip       = None
        self.handout_ip   = None

        self.requested_options = [54,51,58,59]
        self.response_header   = []
        self.response_options  = []

        # assigning local reference to server callbacks through class alias object
        self._server_options_get  = self._Server.options[sock_info.name].get
        self._server_reservations = self._Server.reservations
        # self._server_int_ip = self._Server.intf_settings[sock_info[1]]['ip'].ip # NOTE: depricate? i dont think we need
            # a separate refence for ip now that it is stored as part of the socket info

    # TODO: look at other parent classes, but consider sending data in directly as arg instead of in constructor
    def parse(self):
        data = self._data

        self.xID    = data[4:8]
        self.bcast  = short_unpack(data[10:12])[0] >> 15
        self.ciaddr = IPv4Address(data[12:16]) # ciaddr
        self.chaddr = data[28:44]
        self.mac    = data[28:34].hex()

        data, option_length = data[240:], 0
        for _ in range(61):
            data = data[option_length:]
            if (data[0] == DHCP.END): break

            option_info, data = data[:2], data[2:]
            option_type, option_length = dhcp_opt_unpack(option_info)
            if (option_type == 50):
                self.req_ip = IPv4Address(data[:4]) # constant so hardcoded

            elif (option_type == 53):
                self.mtype = data[0]

            elif (option_type == 54):
                self.server_ident = IPv4Address(data[:4]) # constant so hardcoded

            elif (option_type == 55):
                for option in data[:option_length]:
                    # required options are preloaded into list. this will prevent duplicates.
                    if (option in self.requested_options): continue

                    self.requested_options.append(option)

    # calling internal methods for header and options/payload, then combining byte strings as send data.
    # server options are locked to ensure the config loader thread does not mutate while this is iterating.
    def generate_server_response(self, response_mtype):
        # override the contained record types with DHCP ACK since they are for server use and not to be sent
        if (response_mtype in [DHCP.RENEWING, DHCP.REBINDING]):
            response_mtype = DHCP.ACK

        send_data = [self._generate_dhcp_header()]
        with self._Server.options_lock:
            send_data.append(self._generate_server_options(response_mtype))

        self.send_data = b''.join(send_data)

    def _generate_dhcp_header(self):
        p_time = int(fast_time() - self.init_time)

        return dhcp_header_pack(
            2, 1, 6, 0, self.xID, p_time, 0, self.ciaddr.packed,
            self.handout_ip.packed, self.sock.ip.packed,
            INADDR_ANY.packed, self.chaddr, b'DNX FIREWALL',
            b'\x00'*180, 99, 130, 83, 99
        )

    def _generate_server_options(self, response_mtype):
        # local reference for load fast in tight loop
        requested_options = self.requested_options
        server_option_get = self._server_options_get
        pack_methods = self._pack

        response_options = [dhcp_byte_pack(53, 1, response_mtype)]
        for opt_num in requested_options:
            opt, opt_val = server_option_get(opt_num, _NULL_OPT)
            if (not opt): continue

            opt_len, opt_pack = pack_methods[opt]
            response_options.append(opt_pack(opt_num, opt_len, opt_val))

        response_options.append(double_byte_pack(255, 0))

        return b''.join(response_options)

    @property
    def reservation(self):
        try:
            return self._server_reservations[self.mac]['ip_address']
        except KeyError:
            return None
