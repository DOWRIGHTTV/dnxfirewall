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

    from dnx_gentools.def_exceptions import TerminateSignal
    from dnx_gentools.def_enums import DB_MODE_ALL

    from ddb_connector_sqlite import DBConnector
    # routines will be registered with DBConnector class
    DBConnector.init_routines(DB_MODE_ALL)

    import ddb_main

elif INITIALIZE_MODULE('db-tables'):
    from ddb_connector_sqlite import DBConnector

    with DBConnector() as FirewallDB:
        FirewallDB.create_db_tables()

# export definitions to be used by other modules
else:
    # injecting the database module path into the system path so inter-module imports can resolve.
    import sys
    sys.path.insert(0, __file__.rsplit('/', 1)[0])

    __all__ = ('DBConnector',)

    from ddb_connector_sqlite import DBConnector as DBConnector


def run():
    # init db tables only
    if INITIALIZE_MODULE('db-tables'):
        return

    threading.Thread(target=ddb_main.receive_requests).start()
    try:
        ddb_main.run()
    except (KeyboardInterrupt, TerminateSignal):
        raise

    except Exception as e:
        Log.error(f'Error in ddb_main.run: {e}')
        raise

    finally:
        os.remove(DATABASE_SOCKET)

# ================
# TYPING IMPORTS
# ================
