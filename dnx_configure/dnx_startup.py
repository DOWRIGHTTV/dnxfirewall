#!/usr/bin/env python3

import os, sys
import json

from secrets import token_urlsafe
from pathlib import Path
from subprocess import Popen

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
from dnx_logging.log_main import LogHandler as Log
from dnx_configure.dnx_file_operations import ConfigurationManager
from dnx_configure.dnx_iptables import IPTablesManager as IPTables
from dnx_database.ddb_connector_sqlite import DBConnector

# TODO: initialize Log
LOG_MOD = 'system'

def run():
    # ensuring system allows forwarding. NOTE: probably not required for hardware unit as this is enabled by default.
    IPTables.network_forwarding()

    # changing default action for IPv6 to block everything on all chains in main table
    IPTables.network_forwarding()

    # loading IP Tables from file
    IPTables().restore()

    reset_flask_key()

    # ensuring the default mac address of the wan interface is set. this should only change first time the system initializes
    # setting the mac from None > interface mac. Once the flag has been set, it will not longer change modify default mac value
    configure.set_default_mac_flag()

    create_database_tables()

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
    run()
