#!/usr/bin/env python3

from __future__ import annotations

import threading

from socket import SOL_SOCKET, SO_BROADCAST, SO_BINDTODEVICE, SO_REUSEADDR

from dnx_gentools.def_constants import *
from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import DHCP, PROTO
from dnx_gentools.def_namedtuples import DHCP_RECORD

from dnx_iptools.packet_classes import Listener
from dnx_routines.logging.log_client import LogHandler as Log

from dhcp_server_requests import ServerResponse, ClientRequest
from dhcp_server_automate import Configuration, Leases, DHCP_Lease

LOG_NAME = 'dhcp_server'

RequestID = tuple[str, int]


class DHCPServer(Listener):
    intf_settings: ClassVar[dict] = {}
    options: ClassVar[dict] = {}
    leases:  ClassVar[dict] = {}
    reservations: ClassVar[dict] = {}
    options_lock: Lock = threading.Lock()
    handout_lock: Lock = threading.Lock()

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

        # so we don't need to import/ hardcore the server class reference.
        ClientRequest.set_server_reference(cls)
        cls.set_proxy_callback(func=cls.handle_dhcp)

        # only local server ips or no server ip specified are valid to filter responses to other servers
        # within the broadcast domain.
        # FIXME: ip > int
        cls._valid_idents = [*[intf['ip'].ip for intf in cls.intf_settings.values()], None]

    def _pre_inspect(self, packet) -> bool:
        if (packet.mtype in self._valid_mtypes
                and packet.server_ident in self._valid_idents):
            return True

        return False

    @classmethod
    def handle_dhcp(cls, client_request: ClientRequest):
        '''pseudo alternate constructor acting as a callback for the Parent/Listener class.

        the call will not return the created instance, instead, it will internally manage the instance and ensure the
        request gets handled.'''

        request_id: RequestID = (client_request.mac, client_request.xID)
        server_mtype: DHCP = DHCP.NOT_SET
        record: Optional = None

        Log.debug(f'[request] type={client_request.mtype}, id={request_id}')

        if (client_request.mtype == DHCP.RELEASE):
            self._release(client_request.ciaddr, client_request.mac)

        elif (client_request.mtype == DHCP.DISCOVER):
            server_mtype, record = self._discover(request_id, client_request)

        elif (client_request.mtype == DHCP.REQUEST):
            server_mtype, record = self._request(request_id, client_request)

        # TODO: logging purposes only. probably isn't needed. the below condition are protected by
        # the initiated value being "DHCP.NOT_SET" so we don't need to cover for them.
        else:
            Log.debug(f'[request] Unknown mtype: type={client_request.mtype}, id={request_id}')

        # this is filtering out response types like dhcp nak | modifying lease before
        # sending to ensure a power failure will have persistent record data.
        if (server_mtype not in [DHCP.NOT_SET, DHCP.DROP, DHCP.NAK]):
            self.leases.modify(
                client_request.handout_ip, record
            )

        # only types specified in list require a response.
        if (server_mtype in [DHCP.OFFER, DHCP.ACK, DHCP.NAK]):
            client_request.generate_server_response(server_mtype)

            self.send_to_client(client_request, server_mtype)

    @classmethod
    def _release(cls, ip_address, mac_address: str) -> None:
        dhcp: ServerResponse = ServerResponse(server=self)

        # if mac/ lease mac match, the lease will be removed from the table
        if dhcp.release(ip_address, mac_address):
            self.leases.modify(ip_address)

        else:
            Log.informational(f'[release][{mac_address}] Client attempted invalid release.')

    def _discover(self, request_id: RequestID, client_request: ClientRequest):
        dhcp: ServerResponse = ServerResponse(client_request.sock.name, server=self)
        self._ongoing[request_id] = dhcp

        client_request.handout_ip = dhcp.offer(client_request)

        # NOTE: the final record hostname will be used, so don't need it here
        return DHCP.OFFER, DHCP_RECORD(DHCP.OFFERED, fast_time(), client_request.mac, '')

    def _request(self, request_id: RequestID, client_request) -> tuple[DHCP, Optional[DHCP_Lease]]:
        record: Optional[DHCP_Lease] = None
        request_mtype: DHCP

        dhcp: ServerResponse = self._ongoing.get(request_id, None)
        if (not dhcp):
            dhcp = ServerResponse(client_request.sock.name, server=self)

        request_mtype, handout_ip = dhcp.ack(client_request)
        # responding with ACK
        if (request_mtype in [DHCP.ACK, DHCP.RENEWING, DHCP.REBINDING]):
            client_request.handout_ip = handout_ip
            record = (DHCP.LEASED, fast_time(), client_request.mac, client_request.hostname)

        # sending NAK per rfc 2131
        elif (request_mtype is DHCP.NAK):
            client_request.handout_ip = INADDR_ANY

        # not responding per rfc 2131.
        # else:

        # removing the request from ongoing since we are sending the final message and do
        # not need any objects from the request instance anymore.
        self._ongoing.pop(request_id, None)

        return request_mtype, record

    @staticmethod
    # will send response to client over socket depending on host details it will decide unicast or broadcast
    def send_to_client(client_request: ClientRequest, server_mtype: DHCP) -> None:
        if (server_mtype is DHCP.RENEWING):
            client_request.sock.sendto(client_request.send_data, (f'{client_request.ciaddr}', 68))

            Log.debug(f'[response][unicast] {client_request.ciaddr}')

        # NOTE: sending broadcast because fuck.
        else:
            client_request.sock.sendto(client_request.send_data, (f'{BROADCAST}', 68))

            Log.debug(f'[response][broadcast] {client_request.handout_ip}')

        # NOTE: it seems we cannot support this unless we use raw sockets or inject a static arp entry through syscall
        # If the broadcast bit is not set and 'giaddr' is zero and
        # 'ciaddr' is zero, then the server unicasts DHCPOFFER and DHCPACK
        # messages to the client's hardware address and 'yiaddr' address.  In
        # all cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK
        # messages to 0xffffffff.

    @classmethod
    def listener_sock(cls, intf, _) -> Socket:
        l_sock: Socket = cls.intf_settings[intf].get('l_sock')

        l_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR,1)
        l_sock.setsockopt(SOL_SOCKET, SO_BROADCAST,1)
        l_sock.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, f'{intf}\0'.encode('utf-8'))
        l_sock.bind((str(INADDR_ANY), PROTO.DHCP_SVR))

        Log.debug(f'[{l_sock.fileno()}][{intf}] {cls.__name__} interface bound: {cls.intf_settings}')

        return l_sock


if (INIT_MODULE):
    Log.run(
        name=LOG_NAME
    )
    DHCPServer.run(Log, threaded=False)
