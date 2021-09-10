#!/usr/bin/env python3

import os, sys

from json import loads, dumps
from socket import socket, AF_INET, SOCK_DGRAM
from threading import Thread

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-2]))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import *
from dnx_gentools.standard_tools import looper

__all__ = ('system_action')

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
    '''
    Provisional control class for executing root level commands on the system. Some of the
    functionality, syntax, or format (especially regarding permission management/control)
    may change over time.

        warning: This should not be used to invoke iptable rules at this time.
    '''

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
        except OSError as ose:
            write_log(ose) # log this eventually

        else:
            #data format | module: command: args
            data = loads(data.decode())

            # this may seem redundant, but is mainly for input validation/ ensuring properly formatted data
            # is recvd.
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

def _system_action(data_to_send, delay):
    if (delay):
        fast_sleep(delay)

    try:
        data_to_send = dumps(data_to_send)
    except Exception as e:
        write_log(e)

    else:
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.sendto(data_to_send.encode('utf-8'), (f'{LOCALHOST}', CONTROL_SOCKET))

def system_action(*, delay=NO_DELAY, **kwargs):
    '''
    send requested system control action over local socket to SystemControl class/service. if no delay
    is specified, 0/NO_DELAY will be set as default, otherwise a the action will be handled in a thread
    and executed one delay time is reached.

        expecting: module, command, args as keyword arguments

    if command is a control reference to python function, the "args" kwarg value must be a list of arguments
    that can be passed to the python function.
    '''

    if (not isinstance(delay, int)):
        return

    if (delay):
        Thread(target=_system_action, args=(kwargs, delay)).start()

    else:
         _system_action(kwargs, delay)

if __name__ == '__main__':
    SystemControl.run()
