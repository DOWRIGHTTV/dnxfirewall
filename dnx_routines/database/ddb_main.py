#!/usr/bin/env python3

from __future__ import annotations

import os
import traceback

from socket import socket, AF_UNIX, SOCK_DGRAM, SOCK_CLOEXEC, SOL_SOCKET, SO_PASSCRED

from dnx_gentools.def_constants import TYPE_CHECKING, DATABASE_SOCKET, ONE_SEC, NO_DELAY, fast_sleep, fast_time
from dnx_gentools.def_namedtuples import IPP_EVENT_LOG, DNS_EVENT_LOG, IPS_EVENT_LOG, GEOLOCATION_LOG, INF_EVENT_LOG
from dnx_gentools.standard_tools import dnx_queue, looper

from dnx_iptools.protocol_tools import authenticate_sender

from dnx_routines.logging.log_client import Log

from dnx_control.system.systemd import sysd_notify_ready

from ddb_connector_sqlite import DBConnector

if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Type, NoReturn, Callable, Optional, Union
    from dnx_gentools.def_typing import EVENT_LOGS

    NT_MAP:    dict[str, Type[EVENT_LOGS]]
    NT_LOOKUP: Callable[[str], Optional[Type[EVENT_LOGS]]]

# NOTE: dynamic reference to namedtuples
NT_MAP = {
    nt.__name__: nt for nt in [IPP_EVENT_LOG, DNS_EVENT_LOG, IPS_EVENT_LOG, GEOLOCATION_LOG, INF_EVENT_LOG]
}
NT_LOOKUP = NT_MAP.get

# ====================================================
# SERVICE SOCKET - Initialization
# ====================================================
if os.path.exists(DATABASE_SOCKET):
    os.remove(DATABASE_SOCKET)

_db_service = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC)
_db_service.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)

_db_service.bind(DATABASE_SOCKET.encode())

# NOTE: direct reference to the recvmsg method for perf
_db_service_recvmsg = _db_service.recvmsg

# =======================================
# PRIMARY FUNCTIONS - REDUCED FROM CLASS
# =======================================
# the main service loop to remove the recursive callback of queue handler.
def run() -> NoReturn:
    Log.notice('Database log entry processing queue ready.')
    sysd_notify_ready()

    fail_count = 0
    fail_time = fast_time()
    while True:
        # NOTE: this is blocking inside dnx_queue loop decorator on _write_to_database function.
        with DBConnector(Log) as database:
            _request_handler(database)

        fail_count += 1
        if (not fail_count % 5):
            new_time = fast_time()

            Log.critical(f'Database write failure count reached 5. {new_time-fail_time} seconds since last entry.')

            fail_time = new_time

        fast_sleep(ONE_SEC)

@dnx_queue(Log, name='Database')
def _request_handler(database: DBConnector, job: list) -> None:

    database.execute(*job)

    # NOTE: this might be wasteful
    database.commit_entries()

@looper(NO_DELAY, queue_for_db=_request_handler.add)
def receive_requests(queue_for_db: Callable[[tuple[str, Union[EVENT_LOGS, GEOLOCATION_LOG]]], None]) -> None:
    '''receives database messages plus ancillary authentication data from dnxfirewall mods.
    '''
    try:
        data, anc_data, *_ = _db_service_recvmsg(2048, 256)
    except OSError:
        traceback.print_exc()
        return

    authorized = authenticate_sender(anc_data)
    # dropping message due to failed auth
    if (not authorized):
        Log.warning(f'sender failed to authenticate. sent -> {data.decode()}')
        return

    log: str
    routine: str
    log, routine = data.decode('utf-8').split('|')

    log_tuple: Type[Union[EVENT_LOGS, GEOLOCATION_LOG]] = NT_LOOKUP(f'{routine}_log'.upper())
    # Log.debug(f'tuple reference retrieved: name->{name}, log_tuple->{log_tuple}')

    # bookmark:: continue updating arguments throughout db api to handle the change in log message format.
    #  - see if you can get the typing on log_tuple to stop being lame.
    try:
        log_entry = log_tuple(*log.split(','))
    except:
        Log.critical(f'routine lookup failure -> ({routine})')

    else:
        queue_for_db((routine, log_entry))

        # not validating input because we don't accept unsolicited comms, enforced by unix socket authentication.
        # if there is malformed data from another dnx module, then it will be unrecoverable until a patch can be loaded.
        # data = loads(data.decode())
        #
        # name = data['method']
        #
        # # NOTE: instead of pickle, using json then converting to a py object manually
        # log_tuple = NT_LOOKUP(f'{name}_log'.upper())
        #
        # # Log.debug(f'tuple reference retrieved: name->{name}, log_tuple->{log_tuple}')
        #
        # try:
        #     log_entry = log_tuple(*data['log'])
        # except:
        #     Log.critical(f'routine lookup failure -> ({name})')
        #
        # else:
        #     queue_for_db((name, data['timestamp'], log_entry))
