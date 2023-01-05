#!/usr/bin/env python3

from __future__ import annotations

from json import dumps
from threading import Timer
from socket import socket, AF_INET, SOCK_DGRAM

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import LOG
from dnx_gentools.def_exceptions import ControlError

from dnx_routines.logging.log_client import Log, direct_log

# ==================
# CONTROL SOCKET
# ===================
_control_client: Socket_T = socket(AF_INET, SOCK_DGRAM)
# connect on udp is for convenience on socket send
_control_client.connect(CONTROL_SOCKET)

_control_client_send = _control_client.send

# ==================
# CONTROL UTILITY
# ===================
def _system_action(control_data: ByteString) -> None:
    _control_client_send(control_data)

def system_action(*, delay: int = NO_DELAY, **kwargs) -> None:
    '''
    send requested system control action over local socket to SystemControl class/service.

    if no delay is specified, 0/NO_DELAY will be set as default, otherwise the action will be handled in a thread
    and executed one delay time is reached.

        expecting: module, command, args as keyword arguments

    if command is a control reference to a Python function, the "args" kwarg value must be a list of arguments that
    can be passed to the python function.
    '''
    if not isinstance(delay, int):
        return

    kwargs['auth'] = CONTROL_AUTHENTICATION

    try:
        control_data = dumps(kwargs).encode('utf-8')
    except Exception as E:
        direct_log('system', LOG.ERROR, f'system action failure. command not executed. | {E}')

        raise ControlError(f'system action failure. command not executed. | {E}')

    if (not delay):
        _system_action(control_data)

    else:
        Timer(delay, _system_action, args=(control_data,)).start()

    if (Log.control_audit):
        direct_log('system', LOG.ERROR, f'{kwargs["module"]} sent system command {kwargs["command"]}')
