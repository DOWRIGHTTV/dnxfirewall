#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, Type

__all__ = (
    'DHCPServer', 'Leases',
    'ClientRequest', 'ServerResponse',

    # TYPES
    'DHCPServer_T', 'ClientRequest_T'
)

if (TYPE_CHECKING):

    from dhcp_server import DHCPServer
    from dhcp_server_automate import Leases
    from dhcp_server_requests import ClientRequest, ServerResponse

    # ======
    # TYPES
    # ======
    DHCPServer_T = Type[DHCPServer]
    ClientRequest_T = Type[ClientRequest]
