#!/usr/bin/env python3

import os
import pwd
import threading
import traceback

from socket import socket, AF_UNIX, SOCK_DGRAM, SOL_SOCKET, SO_PASSCRED, SCM_CREDENTIALS
from json import loads

# importing named tuples, then pulling them from namespace before finishing imports.
# ===============================================================
from dnx_gentools.def_namedtuples import *

_NT_LOCAL_REF = {k: v for k, v in globals().items() if k.isupper()}
_NT_LOOKUP = _NT_LOCAL_REF.get
# ===============================================================

from dnx_gentools.def_constants import *
from dnx_gentools.standard_tools import dnx_queue, looper
from dnx_iptools.def_structs import unpack_scm_creds

from dnx_routines.logging.log_client import LogHandler as Log
from dnx_routines.database.ddb_connector_sqlite import DBConnector

LOG_NAME = 'system'

_getuser_info = pwd.getpwuid
_getuser_groups = os.getgrouplist

# ====================================================
# SERVICE SOCKET - initialization
# ====================================================
if os.path.exists(DATABASE_SOCKET):
    os.remove(DATABASE_SOCKET)

_db_service = socket(AF_UNIX, SOCK_DGRAM)
_db_service.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)

_db_service.bind(DATABASE_SOCKET)

# NOTE: direct reference to recvmsg method for perf
_db_service_recvmsg = _db_service.recvmsg

# ----------------------------------------------------
# SERVICE SOCKET - auth validation
# ----------------------------------------------------
def _authenticate_sender(anc_data):
    anc_data = {msg_type: data for _, msg_type, data in anc_data}

    auth_data = anc_data.get(SCM_CREDENTIALS)
    if (not auth_data):
        return False

    pid, uid, gid = unpack_scm_creds(auth_data)
    # USER is a dnxfirewall constant specified in def_constants
    if (_getuser_info(uid).pw_name != USER):
        return False

    return True

# ====================================================
# PRIMARY FUNCTIONS - REDUCED FROM CLASS
# ====================================================
def init():

    threading.Thread(target=_receive_requests).start()

    _run()

# main service loop to remove the recursive callback of queue handler.
def _run():
    print('[+] Starting database log entry processing queue.')
    fail_count = 0
    while True:
        # NOTE: this is blocking inside dnx_queue loop decorator on _write_to_database function.
        with DBConnector(Log) as database:
            _request_handler(database)

        fail_count += 1
        if (not fail_count % 5):
            # TODO: log this as critical or something
            pass

        fast_sleep(ONE_SEC)

@dnx_queue(Log, name='Database')
def _request_handler(database, job):
    method, timestamp, log_info = job

    # NOTE: this might still have issues if callers were missed
    database.execute(timestamp, log_info, routine=method)

    # NOTE: this might be wasteful
    database.commit_entries()


@looper(NO_DELAY, queue_for_db=_request_handler.add)
def _receive_requests(queue_for_db):
    '''receives databases messages plus ancillary authentication data from dnxfirewall mods.'''
    try:
        data, anc_data, *_ = _db_service_recvmsg(2048, 256)
    except OSError:
        traceback.print_exc()

    else:
        authorized = _authenticate_sender(anc_data)

        # dropping message due to failed auth
        if (not authorized):
            return

        # not validating input because we do not accept unsolicited communications and enforced by unix socket
        # authentication. if there is malformed data from other dnx module, then it will be unrecoverable until
        # a patch can be loaded.
        data = loads(data.decode())

        name = data['method']

        # NOTE: instead of pickle, using json then converting to py object manually
        log_tuple = _NT_LOOKUP(f'{name}_log'.upper())
        log_entry = log_tuple(*data['log'])

        queue_for_db((name, data['timestamp'], log_entry))


def RUN_MODULE():
    Log.run(name=LOG_NAME)

    try:
        init()
    finally:
        os.remove(DATABASE_SOCKET)
