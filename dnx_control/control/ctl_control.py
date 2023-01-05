#!/usr/bin/env python3

from __future__ import annotations

import os

from json import loads
from socket import socket, AF_UNIX, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_PASSCRED, SCM_CREDENTIALS

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.standard_tools import looper

from dnx_iptools.def_structs import scm_creds_pack
from dnx_iptools.protocol_tools import change_socket_owner, authenticate_sender

from dnx_routines.logging.log_client import Log


MODULE_PERMISSIONS = {
    'webui': {
        'systemctl start': None,
        'systemctl stop': None,
        'systemctl restart': None,
        'netplan apply': None,
        'reboot': None,
        'shutdown': None,

        # python functions - must be allowed here and a reference provided
        'os.replace': os.replace
    }
}

# ====================
# CONTROL MSG HANDLER
# ====================
# if os.path.exists(CONTROL_SOCKET):
#     os.remove(CONTROL_SOCKET)
#
# _control_service = socket(AF_UNIX, SOCK_DGRAM)
_control_sock: Socket_T = socket(AF_INET, SOCK_DGRAM)
# _control_sock.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
_control_sock.bind(CONTROL_SOCKET)

# change_socket_owner(CONTROL_SOCKET)

_control_service_recv = _control_sock.recv
_control_service_sendmsg = _control_sock.send


class SystemControl:
    '''
    Provisional control class for executing root level commands on the system.

    Some functionality, syntax, or format (especially regarding permission management/control) may change over time.

        warning: This should not be used to invoke iptables commands at this time.
    '''

    # _control_sock = socket()

    @classmethod
    # normally, I wouldn't do this as I try to not have needless classes, but this is one case that will definitely be
    # expanded on to ensure it is a secure implementation and doesn't allow for any funny business.
    def run(cls) -> None:
        self = cls()

        self._receive_control_socket()

    @looper(NO_DELAY)
    def _receive_control_socket(self) -> None:
        try:
            data = _control_service_recv(2048)
        except OSError as ose:
            Log.error(ose)  # log this eventually

        else:
            try:
                # data format | module: command: args
                data = loads(data.decode())
            except:
                return

            control_auth = data.get('auth', (0, 0, b''))
            if (not control_auth):
                return

            authorized = authenticate_sender([(SOL_SOCKET, SCM_CREDENTIALS, scm_creds_pack(*control_auth))])
            # dropping message due to failed auth
            if (not authorized):
                return

            # this may seem redundant, but is mainly for input validation/ ensuring properly formatted data is rcvd.
            try:
                control_ref = MODULE_PERMISSIONS[data['module']][data['command']]
            except KeyError as ke:
                Log.warning(ke)  # log eventually

            else:
                # this allows args to not be specified in kwargs by caller if not needed.
                cmd_args = data.get('args', '')

                # calling returned reference based on string sent by module. ensuring args are specified here
                # as safety. this could still have issues if the args are not a list and would iter over the string.
                if (control_ref and cmd_args):
                    control_ref(*cmd_args)

                # calling partial of run with shell=True
                else:
                    shell(f'{data["command"]} {cmd_args}')
