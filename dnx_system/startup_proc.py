#!/usr/bin/env python3

import __init__

import os
import json

from secrets import token_urlsafe

import dnx_sysmods.configure.configure as configure

from dnx_sysmods.logging.log_main import LogHandler as Log
from dnx_sysmods.configure.file_operations import ConfigurationManager
from dnx_sysmods.configure.iptables import IPTablesManager as IPTables
from dnx_sysmods.database.ddb_connector_sqlite import DBConnector

LOG_NAME = 'system'

# required to prevent cyclical import issues
ConfigurationManager.set_log_reference(Log)

def run():
    # ensuring system allows forwarding. NOTE: probably not required for hardware unit as this is enabled by default.
    IPTables.network_forwarding()

    Log.notice('[startup] network forwarding set.')

    # changing default action for IPv6 to block everything on all chains in main table
    IPTables.block_ipv6()

    Log.notice('[startup] IPv6 disabled.')

    # loading IP Tables from file
    IPTables().restore()

    Log.notice('[startup] IPTables restored.')

    reset_flask_key()

    Log.notice('[startup] Webui/Flask key regenerated.')

    # ensuring the default mac address of the wan interface is set. this should only change first time the system initializes
    # setting the mac from None > interface mac. Once the flag has been set, it will not longer change modify default mac value
    configure.set_default_mac_flag()

    Log.debug('[startup] default mac flag check.')

    create_database_tables()

    Log.debug('[startup] database table maintenance.')

    # exiting service manually due to LogHandler threads
    os._exit(0)

def reset_flask_key():
    with ConfigurationManager('config') as dnx:
        flask_settings = dnx.load_configuration()

        flask_config = flask_settings['flask']
        flask_config['key'] = token_urlsafe(32)

        dnx.write_configuration(flask_settings)

# creating all DB tables if not already done
def create_database_tables():
    with DBConnector() as database:
        database.create_db_tables()

        database.commit_entries()

if __name__ == '__main__':
    Log.run(
        name=LOG_NAME
    )

    run()
