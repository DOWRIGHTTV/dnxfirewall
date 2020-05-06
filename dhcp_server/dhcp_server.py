#!/usr/bin/env python3

import os, sys
import time, subprocess
import threading
import struct
import json
import traceback

from ipaddress import IPv4Address
from socket import socket, error, inet_aton, AF_INET, SOCK_DGRAM
from socket import SOL_SOCKET, SO_BROADCAST, SO_BINDTODEVICE, SO_REUSEADDR

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_iptools.dnx_interface as interface

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_parent_classes import Listener
from dnx_iptools.dnx_structs import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_standard_tools import looper

from dnx_logging.log_main import LogHandler as Log
from dhcp_server.dhcp_server_requests import ServerResponse, ClientRequest
from dhcp_server.dhcp_server_automate import Configuration, Leases

LOG_NAME = 'dhcp_server'


class DHCPServer(Listener):
    intf_settings = {}
    options = {}
    leases  = {} # NOTE: this is pissing me off. it conflicts with custom default dict
    reservations = {}
    options_lock = threading.Lock()
    handout_lock = threading.Lock()

    _valid_mtypes = [DHCP.DISCOVER, DHCP.REQUEST, DHCP.RELEASE]
    _valid_idents = []
    _ongoing = {}

    _packet_parser = ClientRequest

    __slots__ = ()

    @classmethod
    def _setup(cls):
        Configuration.setup(cls)

        # initializing the lease table dictionary and giving a reference to the reservations
        cls.leases = Leases(cls.reservations)

        ClientRequest.set_server_reference(cls)
        cls.set_proxy_callback(func=cls.handle_dhcp)

        cls._valid_idents = [*[intf['ip'].ip for intf in cls.intf_settings.values()], None]

    def _pre_inspect(self, packet):
        if (packet.mtype in self._valid_mtypes
                and packet.server_ident in self._valid_idents):
            return True

        return False

    @classmethod
    def handle_dhcp(cls, packet):
        '''pseudo alternate constructer acting as a callback for the Parent/Listener class, but will not return
        the created instance. instead it will internally manage the instance and ensure the request gets handled.'''

        # NOTE: sending in None to fulfill __init__ requirements in the parent. MAYBE. one day. we can decide if
        # we can to remove the assignments in initialization and inject them via the alternate constructor, allowing
        # classing doing a self callback (non external) to not need to fill in the gap needlessly.
        self = cls(None, None)
        self._handle_request(packet)

    def _handle_request(self, client_request):
        request_id, response_mtype = (client_request.mac, client_request.xID), None
        Log.debug(f'REQ | TYPE={client_request.mtype}, ID={request_id}')

        if (client_request.mtype == DHCP.RELEASE):
            self._release(client_request.ip, client_request.mac)

        elif (client_request.mtype == DHCP.DISCOVER):
            response_mtype, record = self._discover(request_id, client_request)

        elif (client_request.mtype == DHCP.REQUEST):
            response_mtype, record = self._request(request_id, client_request)

        else:
            Log.warning(f'Unknown request type from {client_request.mac}')

        if (response_mtype):
            client_request.generate_server_response(response_mtype)

            # this is filtering out response types like dhcp nak
            if (record):
                self.leases.modify( # pylint: disable=no-member
                    client_request.handout_ip, record
            )

            self.send_to_client(client_request)

    def _release(self, ip_address, mac_address):
        dhcp = ServerResponse(server=self)

        # if mac/ lease mac match, the lease will be removed from the table
        if dhcp.release(ip_address, mac_address):
            self.leases.modify(ip_address, None) # pylint: disable=no-member

    def _discover(self, request_id, client_request):
        dhcp = ServerResponse(client_request.intf, server=self)
        self._ongoing[request_id] = dhcp

        client_request.handout_ip = dhcp.offer(client_request)

        return DHCP.OFFER, (DHCP.OFFERED, fast_time(), client_request.mac)

    def _request(self, request_id, client_request):
        dhcp = self._ongoing.get(request_id, None)
        if (not dhcp):
            dhcp = ServerResponse(client_request.intf, server=self)

        result = dhcp.ack(client_request)
        # not responding per rfc 2131
        if (result == DHCP.DROP):
            self._ongoing.pop(request_id, None)
            response_mtype, record = None, None

        # sending NAK per rfc 2131
        elif (result == DHCP.NAK):
            client_request.handout_ip = INADDR_ANY
            response_mtype, record = DHCP.NAK, None

        # responding with ACK
        elif (result):
            client_request.handout_ip = result
            response_mtype = DHCP.ACK
            record = (DHCP.LEASED, fast_time(), client_request.mac)

        # protecting return on invalid dhcp types | TODO: validate if this even does anything. :)
        else:
            response_mtype, record = None, None

        return response_mtype, record

    @property
    # NOTE: might need to be adjusted due to new listener class
    def is_enabled(self):
        return True

        # if self.intf_settings[self.name]['enabled']: return True

        # return False

    @staticmethod
    # will send response to client over socket depending on host details it will decide unicast or broadcast
    def send_to_client(client_request):
        # TODO: this current has problems so all requests will be broadcast unless they have the unicast
        # flag set and have a valid source ip address. for full unicast support, its looking like a raw
        # socket would have to be used because the dst mac would need to be the request chaddr field.
        if (client_request.bcast and client_request.ip == INADDR_ANY):
            Log.debug(f'Sent BROADCAST to 255.255.255.255:68')
            client_request.sock.sendto(client_request.send_data, (f'{BROADCAST}', 68))

        else:
            Log.debug(f'Sent UNICAST to {client_request.handout_ip}:68')
            client_request.sock.sendto(client_request.send_data, (f'{client_request.handout_ip}', 68))

    @property
    def listener_sock(self):
        l_sock = socket(AF_INET, SOCK_DGRAM)
        l_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR,1)
        l_sock.setsockopt(SOL_SOCKET, SO_BROADCAST,1)
        l_sock.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, f'{self._intf}\0'.encode('utf-8'))
        l_sock.bind((str(INADDR_ANY), PROTO.DHCP_SVR))

        return l_sock

if __name__ == '__main__':
    Log.run(
        name=LOG_NAME,
        verbose=VERBOSE,
        root=ROOT
    )
    DHCPServer.run(Log, threaded=False)
