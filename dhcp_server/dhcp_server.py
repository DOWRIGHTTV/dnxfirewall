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

        # so we dont need to import/ hardcore the server class reference.
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
        request_id, server_mtype, record = (client_request.mac, client_request.xID), DHCP.NOT_SET, None
        Log.debug(f'REQ | TYPE={client_request.mtype}, ID={request_id}')

        if (client_request.mtype == DHCP.RELEASE):
            self._release(client_request.ciaddr, client_request.mac)

        elif (client_request.mtype == DHCP.DISCOVER):
            server_mtype, record = self._discover(request_id, client_request)

        elif (client_request.mtype == DHCP.REQUEST):
            server_mtype, record = self._request(request_id, client_request)

        # TODO: logging purposes only. probably isnt needed. the below condition are protected by
        # the initiated value being "DHCP.NOT_SET" so we dont need to cover for them.
        else:
            Log.warning(f'Unknown request type from {client_request.mac}')

        # this is filtering out response types like dhcp nak | modifying lease before
        # sending to ensure a power failure will have persistent record data.
        if (server_mtype not in [DHCP.NOT_SET, DHCP.DROP, DHCP.NAK]):
            self.leases.modify( # pylint: disable=no-member
                client_request.handout_ip, record
            )

        # only types specified in list require a response.
        if (server_mtype in [DHCP.OFFER, DHCP.ACK, DHCP.NAK]):
            client_request.generate_server_response(server_mtype)

            self.send_to_client(client_request, server_mtype)

    def _release(self, ip_address, mac_address):
        dhcp = ServerResponse(server=self)

        # if mac/ lease mac match, the lease will be removed from the table
        if dhcp.release(ip_address, mac_address):
            self.leases.modify(ip_address) # pylint: disable=no-member

        else:
            Log.warning(f'Client {mac_address} attempted invalid release.')

    def _discover(self, request_id, client_request):
        dhcp = ServerResponse(client_request.sock.name, server=self)
        self._ongoing[request_id] = dhcp

        client_request.handout_ip = dhcp.offer(client_request)

        return DHCP.OFFER, (DHCP.OFFERED, fast_time(), client_request.mac)

    # TODO: troubleshoot this. it seems that requests to confirm or renew a lease are breaking causing a
    # fatal exception. (none type cant be .packed()). look into how we are defining a handout_ip for
    # renewals. we might be doing something wrong or out of order where the initialez value never get
    # overwritten. it could also be the logic in this method is bad and doesnt correctly determine
    # what to do (less likely as it is trying to respond back to requester)
    def _request(self, request_id, client_request):
        # NOTE: assign get method on init?
        dhcp = self._ongoing.get(request_id, None)
        if (not dhcp):
            dhcp = ServerResponse(client_request.sock.name, server=self)

        request_mtype, handout_ip = dhcp.ack(client_request)
        # not responding per rfc 2131
        if (request_mtype is DHCP.DROP):
            record = None

        # sending NAK per rfc 2131
        elif (request_mtype is DHCP.NAK):
            client_request.handout_ip = INADDR_ANY
            record = None

        # responding with ACK
        elif (request_mtype in [DHCP.ACK, DHCP.RENEWING, DHCP.REBINDING]):
            client_request.handout_ip = handout_ip
            record = (DHCP.LEASED, fast_time(), client_request.mac)

        # protecting return on invalid dhcp types | TODO: validate if this even does anything. :)
        else:
            record, request_mtype = None, DHCP.DROP

        # removing the request from ongoing since we are sending the final message and do
        # not need any objects from the request instance anymore.
        self._ongoing.pop(request_id, None)

        return request_mtype, record

    @property
    # NOTE: might need to be adjusted due to new listener class
    def is_enabled(self):
        return True

        # if self.intf_settings[self.name]['enabled']: return True

        # return False

    @staticmethod
    # will send response to client over socket depending on host details it will decide unicast or broadcast
    def send_to_client(client_request, server_mtype):
        if (server_mtype is DHCP.RENEWING):
            client_request.sock.sendto(client_request.send_data, (f'{client_request.ciaddr}', 68))

            Log.debug(f'Sent unicast to {client_request.ciaddr}:68')

        # NOTE: sending broadcast because fuck.
        else:
            client_request.sock.sendto(client_request.send_data, (f'{BROADCAST}', 68))

            Log.debug(f'Sent broadcast for {client_request.handout_ip} to 255.255.255.255:68')

        # NOTE: it seems we cannot support this unless we use raw sockets or inject a static arp entry through syscall
        # If the broadcast bit is not set and 'giaddr' is zero and
        # 'ciaddr' is zero, then the server unicasts DHCPOFFER and DHCPACK
        # messages to the client's hardware address and 'yiaddr' address.  In
        # all cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK
        # messages to 0xffffffff.

    @staticmethod
    def listener_sock(intf, intf_ip):
        l_sock = socket(AF_INET, SOCK_DGRAM)
        l_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR,1)
        l_sock.setsockopt(SOL_SOCKET, SO_BROADCAST,1)
        l_sock.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, f'{intf}\0'.encode('utf-8'))
        l_sock.bind((str(INADDR_ANY), PROTO.DHCP_SVR))

        return l_sock

if __name__ == '__main__':
    Log.run(
        name=LOG_NAME
    )
    DHCPServer.run(Log, threaded=False)
