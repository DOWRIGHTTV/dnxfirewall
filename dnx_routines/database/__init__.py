#!/usr/bin/env python3

from __future__ import annotations

# ================
# RUNTIME IMPORTS
# ================
from dnx_gentools.def_constants import INITIALIZE_MODULE, DATABASE_SOCKET

if INITIALIZE_MODULE('database'):
    __all__ = ('run',)

    import os
    import threading

    from dnx_routines.logging.log_client import LogHandler as Log

    Log.run(name='system')

    import ddb_main

def run():

    threading.Thread(target=ddb_main.receive_requests).start()
    try:
        ddb_main.run()
    finally:
        os.remove(DATABASE_SOCKET)


# ================
# TYPING IMPORTS
# ================
from typing import TYPE_CHECKING, Type

if (TYPE_CHECKING):
    __all__ = (
        'DBConnector',

        # Types
        'DBConnector_T'
    )

    from typing import TYPE_CHECKING, Type

    if (TYPE_CHECKING):
        from ddb_connector_sqlite import DBConnector

        DBConnector_T = Type[DBConnector]
