#!/usr/bin/env python3

from __future__ import annotations

from socket import SOL_SOCKET, SO_BROADCAST, SO_BINDTODEVICE, SO_REUSEADDR

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import DHCP, PROTO
from dnx_gentools.def_namedtuples import DHCP_RECORD

from dnx_iptools.packet_classes import Listener
from dnx_iptools.cprotocol_tools import itoip

from dnx_routines.logging.log_client import Log

from dhcp_server_requests import ServerResponse, ClientRequest
from dhcp_server_automate import Configuration, Leases

__all__ = (
    'DHCPServer',
)

LOG_NAME = 'dhcp_server'

# NOTE: this type of type hint confuses me
RequestID: tuple[str, int]
VALID_MTYPES: list[DHCP] = [DHCP.DISCOVER, DHCP.REQUEST, DHCP.RELEASE]
RESPONSE_REQUIRED: list[DHCP] = [DHCP.OFFER, DHCP.ACK, DHCP.NAK]
RECORD_NOT_NEEDED: list[DHCP] = [DHCP.NOT_SET, DHCP.DROP, DHCP.NAK]


class DHCPServer(Listener):
    intf_settings: ClassVar[dict] = {}
    valid_idents:  ClassVar[set[int]] = {0}

    # initializing the lease table dictionary and providing a reference to the reservations dict
    leases: ClassVar[Leases] = Leases()

    _ongoing: ClassVar[dict] = {}

    _packet_parser: ClassVar[ClientRequest_T] = ClientRequest

    __slots__ = ()

    @classmethod
    def _setup(cls):
        Log.notice('DHCPServer initialization started.')

        Configuration.setup(cls)

        # so we don't need to import/ hardcore the server class reference.
        ClientRequest.set_server_references(cls.intf_settings)
        cls.set_proxy_callback(func=cls.handle_dhcp)

    Log.notice('DHCPServer initialization complete.')

    def _pre_inspect(self, packet) -> bool:
        if (packet.mtype in VALID_MTYPES and packet.server_ident in self.valid_idents):
            return True

        return False

    def handle_dhcp(self, client_request: ClientRequest):
        '''pseudo alternate constructor acting as a callback for the Parent/Listener class.

        the call will not return the created instance, instead, it will internally manage the instance and ensure the
        request gets handled.
        '''
        request_id: RequestID = (client_request.mac, client_request.xID)
        server_mtype: DHCP = DHCP.NOT_SET
        record: Optional[DHCP_RECORD] = None

        Log.debug(f'[request] type={client_request.mtype}, id={request_id}')

        # ==============
        # RELEASE
        # ==============
        if (client_request.mtype == DHCP.RELEASE):

            # if mac/ lease mac match, the lease will be removed from the table
            if ServerResponse.release(client_request.ciaddr, client_request.mac):
                self.__class__.leases.modify(client_request.ciaddr)

            else:
                Log.informational(f'[release][{client_request.mac}] Client attempted invalid release.')

        # ==============
        # DISCOVER
        # ==============
        elif (client_request.mtype == DHCP.DISCOVER):
            dhcp: ServerResponse = ServerResponse(client_request.recvd_intf)

            self.__class__._ongoing[request_id] = dhcp
            client_request.handout_ip = dhcp.check_offer(client_request)

            # NOTE: the final record hostname will be used, so don't need it here
            server_mtype = DHCP.OFFER
            record = DHCP_RECORD(DHCP.OFFERED, fast_time(), client_request.mac, '')

        # ==============
        # REQUEST
        # ==============
        elif (client_request.mtype == DHCP.REQUEST):
            server_mtype: DHCP
            record: Optional[DHCP_RECORD] = None

            dhcp: ServerResponse = self._ongoing.get(request_id, None)
            if (not dhcp):
                dhcp = ServerResponse(client_request.recvd_intf)

            server_mtype, handout_ip = dhcp.check_ack(client_request)
            # responding with ACK
            if (server_mtype in [DHCP.ACK, DHCP.RENEWING, DHCP.REBINDING]):
                client_request.handout_ip = handout_ip
                record = DHCP_RECORD(DHCP.LEASED, fast_time(), client_request.mac, client_request.hostname)

            # sending NAK per rfc 2131
            elif (server_mtype is DHCP.NAK):
                client_request.handout_ip = INADDR_ANY

            # not responding per rfc 2131.
            # else:

            # removing the request from ongoing since we are sending the final message and do
            # not need any objects from the request instance anymore.
            self._ongoing.pop(request_id, None)

        # ==============
        # UNKNOWN/DEBUG
        # ==============
        else:
            Log.debug(f'[request] Unknown mtype: type={client_request.mtype}, id={request_id}')

        # this is filtering out response types like dhcp nak | modifying lease before
        # sending to ensure a power failure will have persistent record data.
        if (server_mtype not in RECORD_NOT_NEEDED):
            self.leases.modify(client_request.handout_ip, record)

        # only types specified in the list require a response.
        if (server_mtype in RESPONSE_REQUIRED):
            send_data = client_request.generate_server_response(server_mtype)

            send_to_client(send_data, client_request, server_mtype)

    @classmethod
    def listener_sock(cls, intf, _) -> Socket:
        l_sock: Socket = cls.intf_settings[intf].get('l_sock')

        l_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        l_sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        l_sock.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, f'{intf}\0'.encode('utf-8'))
        l_sock.bind((itoip(INADDR_ANY), PROTO.DHCP_SVR))

        Log.debug(f'[{l_sock.fileno()}][{intf}] {cls.__name__} interface bound: {cls.intf_settings}')

        return l_sock


def send_to_client(send_data: bytearray, client_request: ClientRequest, server_mtype: DHCP) -> None:
    if (server_mtype is DHCP.RENEWING):
        client_request.sendto(send_data, (f'{client_request.ciaddr}', 68))

        Log.debug(f'[response][unicast] {client_request.ciaddr}')

    # NOTE: sending broadcast because fuck.
    else:
        client_request.sendto(send_data, (f'{BROADCAST}', 68))

        Log.debug(f'[response][broadcast] {client_request.handout_ip}')

    # NOTE: it seems we cannot support this unless we use raw sockets or inject a static arp entry through syscall
    # If the broadcast bit is not set and 'giaddr' is zero and
    # 'ciaddr' is zero, then the server unicasts DHCPOFFER and DHCPACK
    # messages to the client's hardware address and 'yiaddr' address.  In
    # all cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK
    # messages to 0xffffffff.

def run():
    DHCPServer.run(Log, threaded=False)


if (INIT_MODULE == LOG_NAME):
    Log.run(
        name=LOG_NAME
    )
