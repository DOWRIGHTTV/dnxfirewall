#!/usr/bin/env python3

import os, sys
import time
import threading
import shutil

from json import loads, dumps
from socket import socket, AF_INET, SOCK_DGRAM

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import shell, LOCALHOST, CONTROL_SOCKET, NO_DELAY
from dnx_iptools.dnx_standard_tools import looper

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


class SystemControl:

    _control_sock = socket()

    @classmethod
    def run(cls):
        self = cls()

        self._create_control_sock()

        # NOTE: direct reference to recv method for perf
        self._control_sock_recv = self._control_sock.recv

        self._receive_control_socket()

    def _create_control_sock(self):
        self._control_sock = socket(AF_INET, SOCK_DGRAM)
        self._control_sock.bind((f'{LOCALHOST}', CONTROL_SOCKET))

    @looper(NO_DELAY)
    def _receive_control_socket(self):
        try:
            data = self._control_sock_recv(2048)
        except OSError:
            pass # log this eventually

        else:
            #data format | module: command: args
            data = loads(data.decode())

            # this may seem redundant, but is mainly for input validation/ ensuring properly formatted data
            # is recvd.
            try:
                control_ref = MODULE_PERMISSIONS[data['module']][data['command']]

                cmd_args = data['args']
            except KeyError:
                pass # log eventually

            else:
                # calling returned reference based on string sent by module.
                if (control_ref):
                    control_ref(*cmd_args)

                # calling partial of run with shell=True
                else:
                    shell(f'{data["command"]} {cmd_args}')

def system_action(*, module, command, args):
    '''send requested system control action over local socket to SystemControl class/service'''

    sock = socket(AF_INET, SOCK_DGRAM)

    sock.sendto(dumps(locals()).encode('utf-8'), (LOCALHOST, CONTROL_SOCKET))
