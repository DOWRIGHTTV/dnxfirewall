#!/usr/bin/env python3

import __init__

import os
from json import loads
from socket import socket, AF_UNIX, SOCK_DGRAM

from dnx_gentools.def_constants import *
from dnx_gentools.standard_tools import looper

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

_control_service = socket(AF_UNIX, SOCK_DGRAM)
_control_service.bind(CONTROL_SOCKET)

_control_service_recv = _control_service.recvmsg
_control_service_sendmsg = _control_service.sendmsg


class SystemControl:
    '''
    Provisional control class for executing root level commands on the system. Some functionality, syntax, or format
    (especially regarding permission management/control) may change over time.

        warning: This should not be used to invoke iptables commands at this time.
    '''

    _control_sock = socket()

    @classmethod
    # normally I wouldn't do this as I try to not have needless classes, but this is one case that will definitely be
    # expanded on to ensure it is a secure implementation and doesn't allow for any funny business.
    def run(cls):
        cls()

    @looper(NO_DELAY)
    def _receive_control_socket(self):
        try:
            data, *_ = _control_service_recv(2048)
        except OSError as ose:
            write_log(ose) # log this eventually

        else:
            # data format | module: command: args
            data = loads(data.decode())

            # this may seem redundant, but is mainly for input validation/ ensuring properly formatted data
            # is rcvd.
            try:
                control_ref = MODULE_PERMISSIONS[data['module']][data['command']]
            except KeyError as ke:
                write_log(ke) # log eventually

            else:
                # this allows args to not be specified in kwargs by caller if not needed.
                cmd_args = data.get('args', '')

                # calling returned reference based on string sent by module. ensuring args are specified here
                # as a safety. this could still have issues if the args are not a list and would iter over the string.
                if (control_ref and cmd_args):
                    control_ref(*cmd_args)

                # calling partial of run with shell=True
                else:
                    shell(f'{data["command"]} {cmd_args}')

if (__name__ == '__main__'):
    SystemControl.run()