#!/usr/bin/env python3

from __future__ import annotations

# ================
# RUNTIME IMPORTS
# ================
from dnx_gentools.def_constants import INITIALIZE_MODULE

if INITIALIZE_MODULE('dhcp-server'):
    __all__ = ('run',)

    from dnx_routines.logging.log_client import Log

    Log.run(name='dhcp_server')

    from dhcp_server import DHCPServer

def run():
    DHCPServer.run(Log)


# ================
# TYPING IMPORTS
# ================
from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from typing import Type, TypeAlias

    __all__ = (
        'DHCPServer', 'Leases',
        'ClientRequest', 'ServerResponse',

        # TYPES
        'DHCPServer_T', 'ClientRequest_T',

        'RequestID'
    )

    RequestID: TypeAlias = tuple[str, int]

    from dhcp_server import DHCPServer
    from dhcp_server_automate import Leases
    from dhcp_server_requests import ClientRequest, ServerResponse

    # ======
    # TYPES
    # ======
    DHCPServer_T:    TypeAlias = Type[DHCPServer]
    ClientRequest_T: TypeAlias = Type[ClientRequest]
