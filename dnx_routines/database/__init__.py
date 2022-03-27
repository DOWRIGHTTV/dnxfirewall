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

if INITIALIZE_MODULE('db-tables'):
    from ddb_connector_sqlite import DBConnector

    with DBConnector() as FirewallDB:
        FirewallDB.create_db_tables()

def run():
    # init db tables only
    if INITIALIZE_MODULE('db-tables'):
        return

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

    from ddb_connector_sqlite import DBConnector

    DBConnector_T = Type[DBConnector]
