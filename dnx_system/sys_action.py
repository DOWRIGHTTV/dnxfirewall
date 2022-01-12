#!/usr/bin/env python3

from json import dumps
from threading import Thread
from socket import socket, AF_UNIX, SOCK_DGRAM

from dnx_gentools.def_constants import *

# ==================
# CONTROL SOCKET
# ===================

_control_client = socket(AF_UNIX, SOCK_DGRAM)
try:
    _control_client.connect(CONTROL_SOCKET)
except FileNotFoundError:
    print('control socket conn failed.')

_control_client_sendmsg = _control_client.sendmsg

# ==================
# CONTROL UTILITY
# ===================

def _system_action(data_to_send, delay):
    if (delay):
        fast_sleep(delay)

    try:
        data_to_send = dumps(data_to_send).encode('utf-8')
    except Exception as e:
        console_log(e)

    else:
        _control_client_sendmsg(data_to_send, DNX_AUTHENTICATION)

def system_action(*, delay=NO_DELAY, **kwargs):
    '''
    send requested system control action over local socket to SystemControl class/service. if no delay
    is specified, 0/NO_DELAY will be set as default, otherwise the action will be handled in a thread
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
