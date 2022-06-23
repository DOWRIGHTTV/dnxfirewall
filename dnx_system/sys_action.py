#!/usr/bin/env python3

from __future__ import annotations

from json import dumps
from threading import Timer
from socket import socket, AF_UNIX, SOCK_DGRAM, SOL_SOCKET, SCM_CREDENTIALS

from source.web_typing import *

from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import LOG
from dnx_gentools.def_exceptions import ControlError

from dnx_routines.logging.log_client import Log, direct_log

# ==================
# CONTROL SOCKET
# ===================
# TODO: make this recoverable -> function to reconnect as needed
_control_client = socket(AF_UNIX, SOCK_DGRAM)
try:
    _control_client.connect(CONTROL_SOCKET.encode())
except FileNotFoundError:
    print('control socket conn failed.')

_control_client_sendmsg = _control_client.sendmsg

# ==================
# CONTROL UTILITY
# ===================
def _system_action(data_to_send: ByteString) -> None:
    _control_client_sendmsg(data_to_send, [(SOL_SOCKET, SCM_CREDENTIALS, DNX_AUTHENTICATION)])

def system_action(*, delay: int = NO_DELAY, **kwargs) -> None:
    '''
    send requested system control action over local socket to SystemControl class/service.

    if no delay is specified, 0/NO_DELAY will be set as default, otherwise the action will be handled in a thread
    and executed one delay time is reached.

        expecting: module, command, args as keyword arguments

    if command is a control reference to a Python function, the "args" kwarg value must be a list of arguments that
    can be passed to the python function.
    '''
    try:
        data_to_send = dumps(kwargs).encode('utf-8')
    except Exception as E:
        direct_log('system', LOG.ERROR, f'system action failure. command not executed. | {E}')

        raise ControlError(f'system action failure. command not executed. | {E}')

    action = Timer(delay, _system_action, args=(data_to_send,))

    try:
        action.start()

    # this will catch type or value exceptions primarily and any other unexpected errors.
    except Exception as E:
        direct_log('system', LOG.ERROR, f'system action failure. command not executed. | {E}')

        raise ControlError(f'system action failure. command not executed. | {E}')

    if (Log.control_audit):
        direct_log('system', LOG.ERROR, f'{kwargs["module"]} sent system command {kwargs["command"]}')
