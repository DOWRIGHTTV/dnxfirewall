#!/usr/bin/env python3

from __future__ import annotations

import os

from secrets import token_urlsafe

import dnx_iptools.interface_ops as interface

from dnx_gentools.def_constants import INITIALIZE_MODULE
from dnx_gentools.file_operations import ConfigurationManager

from dnx_routines.logging.log_client import Log
from dnx_iptools.iptables import IPTablesManager as IPTables
from dnx_routines.database.ddb_connector_sqlite import DBConnector

LOG_NAME = 'system'

# required to prevent cyclical import issues
ConfigurationManager.set_log_reference(Log)

def run():
    # ensuring the system allows forwarding. probably not required for hardware unit as this is enabled by default.
    IPTables.network_forwarding()

    Log.notice('[startup] network forwarding set.')

    # changing default action for IPv6 to block everything on all chains in the main table
    IPTables.block_ipv6()

    Log.notice('[startup] IPv6 disabled.')

    # loading IP Tables from file
    IPTables().restore()

    Log.notice('[startup] IPTables restored.')

    reset_flask_key()

    Log.notice('[startup] Webui/Flask key regenerated.')

    # ensuring the default mac address of the wan interface is set. this should only change first time the system
    # initializes setting the mac from None > interface mac. Once the flag has been set, it will no longer change
    # modify default mac value
    set_default_mac_flag()

    Log.debug('[startup] default mac flag check.')

    create_database_tables()

    Log.debug('[startup] database table maintenance.')

    # exiting service manually due to LogHandler threads
    os._exit(0)

def reset_flask_key():
    with ConfigurationManager('system') as dnx:
        flask_settings = dnx.load_configuration()

        flask_settings['flask->key'] = token_urlsafe(32)

        dnx.write_configuration(flask_settings.expanded_user_data)

def set_default_mac_flag():
    with ConfigurationManager('system') as dnx:
        dnx_settings = dnx.load_configuration()

        if (not dnx_settings['interfaces->builtins->wan->mac_set']):

            wan_intf = dnx_settings['interfaces->builtins->wan->ident']

            dnx_settings['interfaces->builtins->wan->default_mac'] = interface.get_mac_string(interface=wan_intf)
            dnx_settings['interfaces->builtins->wan->mac_set'] = True

        dnx.write_configuration(dnx_settings.expanded_user_data)

# creating all DB tables if not already done
def create_database_tables():
    with DBConnector() as database:
        database.create_db_tables()

        # only standard db writes auto commit
        database.commit_entries()


if INITIALIZE_MODULE('startup'):
    Log.run(
        name=LOG_NAME
    )
