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
from dnx_configure.dnx_interface_services import interface_bandwidth
from dnx_configure.dnx_file_operations import ConfigurationManager
from dnx_configure.dnx_iptables import IPTableManager as IPTables
from dnx_database.ddb_connector_sqlite import DBConnector
from dnx_logging.log_main import LogHandler

__all__ = (
    'Startup'
)

# TODO: initialize Log
LOG_MOD = 'system'

_run_script = False

class Startup:
    def run(self):
        self.apply_network_forwarding()
        self.configure_ipv6_iptables()
        self.restore_iptables()
        self.reset_flask_key()
        self.reset_update_flags()
        self.create_database_tables()

    # ensuring system allows forwarding. NOTE: probably not required for hardware unit as this is enabled by default.
    def apply_network_forwarding(self):
        IPTables.network_forwarding()

    # changing default action for IPv6 to block everything on all chains in main table
    def configure_ipv6_iptables(self):
        IPTables.block_ipv6()

    # loading IP Tables from file
    def restore_iptables(self):
        IPTables().restore()

    def reset_flask_key(self):
        with ConfigurationManager('config') as dnx:
            flask_settings = dnx.load_configuration()

            flask_config = flask_settings['settings']['flask']
            flask_config['key'] = token_urlsafe(32)

            dnx.write_configuration(flask_settings)

    # Resetting system/signatures flags to default
    def reset_update_flags(self):
        configure.set_default_mac_flag()

    # Creating all DB tables if not already done
    def create_database_tables(self):
        with DBConnector() as database:
            database.create_db_tables()

            database.commit_entries()

if __name__ == '__main__':
    Start = Startup()
    Start.run()