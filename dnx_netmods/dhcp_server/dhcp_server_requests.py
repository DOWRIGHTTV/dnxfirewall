#!/usr/bin/env python3

from __future__ import annotations

import random

from ipaddress import IPv4Address

from dnx_gentools.def_constants import *
from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import DHCP

from dnx_iptools.def_structs import *
from dnx_iptools.protocol_tools import icmp_reachable, itoba

from dnx_routines.logging.log_client import LogHandler as Log

_NULL_OPT = (0, '')
_fast_choice = random.choice

__all__ = (
    'ServerResponse', 'ClientRequest'
)


class ServerResponse:
    __slots__ = (
        '_svr', '_request', '_lease_time',
        '_check_icmp_reach',

        '_handout_range', '_net_hosts'
    )

    def __init__(self, intf=None, *, server: DHCPServer):
        self._svr = server

        # if interface ident is sent in we will assign config values. offer/ ack require these
        # values while release does not.
        if (intf):
            intf_settings = server.intf_settings[intf]
            intf_net    = intf_settings['ip'].network
            range_start = intf_settings['lease_range']['start']
            range_end   = intf_settings['lease_range']['end'] + 1
            self._check_icmp_reach = intf_settings['icmp_check']

            self._net_hosts = set(intf_net.hosts())
            self._handout_range = list(intf_net)[range_start:range_end]

    # if the client sends a dhcp release, will ensure client info matches current lease then remove lease from table
    def release(self, ip_address, mac_address: str) -> bool:
        '''release ip address lease stored in server. listener/server instance required.'''

        _, lease_time, lease_mac, _ = self._svr.leases[ip_address]
        if (lease_time != DHCP.RESERVATION and lease_mac == mac_address):
            return True

        return False

    # TODO: ensure that if lease range gets changed while running, any client outside of new range
        # will have their requested ip ignored if it falls outside of the new range.
    # TODO: only allow one lease per host. when i host is given a new lease, check that it doesnt
        # already have one (looking at you linux). if multiple are present, clear out all but most recent.
        # this can potentially just be a recurring clean up job instead of at the time of handout.
    def offer(self, discover):
        reservation = discover.reservation(self._net_hosts)
        if (reservation):
            return reservation

        is_available, lease_mac = self._is_available(discover.req_ip, mac=True)

        # outcome 1/2 in rfc 2131
        if ((discover.ciaddr != INADDR_ANY)
                and (lease_mac == discover.mac or is_available)):

            # ensuring the requested ip address falls within the currently configured handout range for the
            # interface/ network the request was received on.
            return discover.ciaddr if discover.ciaddr in self._handout_range else self._get_available_ip()

        # outcome 3 in rfc 2131
        if (discover.req_ip and is_available):

            # ensuring the requested ip address falls within the currently configured handout range for the
            # interface/ network the request was received on.
            return discover.req_ip if discover.req_ip in self._handout_range else self._get_available_ip()

        # outcome 4 in rfc 2131
        return self._get_available_ip()

    def ack(self, request):
        self._request = request
        self._lease_time, _, lease_mac, _ = self._svr.leases[request.req_ip]

        # DHCP.SELECTING
        if (self.selecting):
            # extra validation to ensure an offer cannot be stolen by another client. rfc does not mention this.
            if (lease_mac != request.mac):
                return DHCP.DROP, None

            return DHCP.ACK, request.req_ip

        # DHCP.INIT_REBOOT
        elif (self.init_reboot):
            # client request from a different network, responding with NAK
            if (request.req_ip not in self._handout_range):
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

        # NOTE: sometimes a request falls outside the standard RFC conditions. this will prevent
        # the server from halting if so.
        return DHCP.DROP, None

    @property
    def selecting(self) -> bool:
        request = self._request
        if (request.ciaddr == INADDR_ANY
                and request.server_ident and request.req_ip):
            return True

        return False

    @property
    def init_reboot(self) -> bool:
        request = self._request
        if (not request.server_ident and request.req_ip):
            return True

        return False

    @property
    def lease_active(self) -> bool:
        request = self._request
        if (request.ciaddr != INADDR_ANY
                and not request.server_ident and not request.req_ip):
            return True

        return False

    @property
    def rebinding(self) -> bool:
        if (fast_time() - self._lease_time >= 74025):
            return True

        return False

    @property
    def renewing(self) -> bool:
        if (43200 <= fast_time() - self._lease_time < 74025):
            return True

        return False

    # generate available random IP in network range. if no ip is available None will be returned.
    # If icmp reachability check is enabled, and the ip is reachable, the process will continue
    # until a valid ip is selected or loop is exhausted

    # TODO: as the available ip addresses gets closer to 0% it, it will be increasingly harder
    # for this function to find and available ip. realistically, it would be likely that many requests
    # would fail since the iteration uses the total count in range, but random choice can return duplicates.
    # how can we ensure the range is actually filled vs getting a random miss on available ip space.
    def _get_available_ip(self):
        handout_range = self._handout_range
        for _ in range(len(handout_range)):
            ip_address = _fast_choice(handout_range)

            if not self._is_available(ip_address): continue

            if (self._check_icmp_reach): # TODO: figure out how we will get notified
                if icmp_reachable(ip_address): continue

            return ip_address
        else:
            Log.critical('IP handout error. No available IPs in range.') # TODO: comeback

    def _is_available(self, ip_address, mac=False):
        '''returns True if the ip address is available to lease out. if mac is set to True a tuple of status and
        associated mac, if any, will be returned.'''
        try:
            lease_status, _, lease_mac, _ = self._svr.leases[ip_address]
        except ValueError:
            Log.error(f'[dhcp/requests] lease lookup error. returned={self._svr.leases[ip_address]}')

        status = True if lease_status is DHCP.AVAILABLE else False

        return status if not mac else status, lease_mac


class ClientRequest:

    _server: ClassVar[Optional[Type[DHCPServer]]] = None
    _pack: ClassVar[dict[int, list[int, Callable]]] = {
        -1: [4, dhcp_ip_pack],
        1: [1, dhcp_byte_pack],
        2: [2, dhcp_short_pack],
        4: [4, dhcp_long_pack]
    }

    __slots__ = (
        'init_time', 'server_ident', 'mtype', 'req_ip',
        'handout_ip', 'hostname', 'requested_options',
        'bcast', 'xID', 'ciaddr', 'chaddr', 'mac',
        'sock',

        # local references to callbacks
        '_server_options'
    )

    @classmethod
    def set_server_reference(cls, server_reference):
        '''setting the class object alias "_Server" as the passed in reference object. this is required as all
        methods in this class rely on the alias reference.'''

        cls._server = server_reference

    def __init__(self, address, sock_info):
        # NOTE: sock_info (namedtuple): name ip socket send sendto recvfrom

        self.sock = sock_info

        self.init_time    = fast_time()
        self.server_ident = None
        self.mtype        = None
        self.req_ip       = None
        self.handout_ip   = None
        self.hostname     = ''

        self.requested_options: list[int] = [54, 51, 58, 59]

        # assigning local reference to server callbacks through class alias object
        self._server_options = self._server.options[sock_info.name]

    # TODO: convert IPAddress to using the raw int.
    def parse(self, data: bytearray) -> None:

        dhcp_header = dhcp_header_unpack(data)

        self.xID:   int = dhcp_header[4]
        self.bcast: int = dhcp_header[6] & DHCP_MASK.BCAST

        self.ciaddr: IPv4Address = IPv4Address(dhcp_header[7])
        self.chaddr: bytes = data[28:44]
        self.mac: str = dhcp_header[11:17].hex()

        data = data[240:]
        for _ in range(61):

            if (data[0] == DHCP.END):
                break

            opt_val, opt_len, data = data[0], data[1], data[2:]
            # opt_attrs = {12: 'hostname', 50: 'req_ip', 53: 'mtype', 54: 'server_ident'}

            if (opt_val == 12):
                self.hostname = data[:opt_len].decode(errors='replace')

            elif (opt_val == 50):
                self.req_ip = IPv4Address(data[:4])  # constant so hardcoded

            elif (opt_val == 53):
                self.mtype = data[0]

            elif (opt_val == 54):
                self.server_ident = IPv4Address(data[:4])  # constant so hardcoded

            elif (opt_val == 55):
                for option in data[:opt_len]:
                    # required options are preloaded into the list to prevent duplicates.
                    if (option not in self.requested_options):
                        self.requested_options.append(option)

            data = data[opt_len:]

    # calling internal methods for header and options/payload, then combining byte strings as send data.
    # server options are locked to ensure the config loader thread does not mutate while this is iterating.
    def generate_server_response(self, response_mtype: DHCP) -> bytearray:

        # override the contained record types with DHCP ACK since they are for server use and not to be sent
        if (response_mtype in [DHCP.RENEWING, DHCP.REBINDING]):
            response_mtype = DHCP.ACK

        # =====================
        # DHCP RESPONSE HEADER
        # =====================
        dhcp_header = bytearray(44)

        dhcp_header[:4] = qb_pack(2, 1, 6, 0)
        dhcp_header[4:8] = long_pack(self.xID)
        dhcp_header[8:10] = int(fast_time() - self.init_time)
        dhcp_header[10:12] = 0
        dhcp_header[12:16] = self.ciaddr.packed
        dhcp_header[16:20] = self.handout_ip.packed
        dhcp_header[20:24] = self.sock.ip.packed
        dhcp_header[24:28] = INADDR_ANY.packed
        dhcp_header[28:44] = self.chaddr

        dhcp_header += b'dnxfirewall\x00'
        dhcp_header += b'\x00'*180
        dhcp_header += qb_pack(99, 130, 83, 99)

        # =====================
        # DHCP RESPONSE OPTS
        # =====================
        # local reference for load fast in tight loop
        server_option_get = self._server_options.get
        pack_opt = self._pack

        response_options = bytearray([53, 1, response_mtype])

        with self._server.options_lock:
            for opt_num in self.requested_options:

                opt, opt_val = server_option_get(opt_num, _NULL_OPT)
                if (opt):
                    opt_len, opt_pack = pack_opt[opt]
                    response_options += opt_pack(opt_num, opt_len, opt_val)

            response_options += double_byte_pack(255, 0)

        return dhcp_header + response_options

    # NOTE: recently changed this to ensure reservations aren't used if they are for a network
    # different that what the request came in on.
    def reservation(self, network_hosts: IPv4Network) -> Optional[IPv4Address]:
        try:
            reserved_ip: IPv4Address = self._server.reservations[self.mac]['ip_address']
        except KeyError:
            return None

        return reserved_ip if reserved_ip in network_hosts else None
