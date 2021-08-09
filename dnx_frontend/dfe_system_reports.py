#!/usr/bin/python3

import json
import sys, os, time

from flask import Flask, render_template, redirect, url_for, request, session

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_system_info import Interface, System, Services
from dnx_database.ddb_connector_sqlite import DBConnector

def load_page(uri_query):
    # if sent from dashboard link, infected clients table will open directly.
    if uri_query.get('view_clients', None):
        return load_infected_clients()

    return get_table_data(action='blocked', table='dnsproxy', method='last'), '1', '1'

def update_page(form):
    table_type = form.get('table', 'db_time')
    selected_num = {
        'db_time': '1', 'db_count': '2', 'dv_time': '3', 'dv_count': '4',
        'ad_time': '5', 'ad_count': '6',

        'iph_block_time':'7',  'iph_view_time':'8',  'iph_all_time':'9',

        'ips_time':'10',
        'ic_all': '11'
    }

    # TODO: bring validation up to speed (ensure host is valid mac format). make database raise validation error if the when removing
    # a client that isnt present in the db. this means some tomfoolery happened and we should return
    # invalid form error.
    menu_option = selected_num.get(table_type, '1')
    if ('i_client_remove' in form):
        infected_client = form.get('infected_client', None)
        detected_host = form.get('detected_host', None)
        if (not infected_client or not detected_host):
            return None # NOTE: should this be an error?

        with DBConnector() as FirewallDB:
            FirewallDB.infected_remove(infected_client, detected_host, table='infectedclients')

            FirewallDB.commit_entries()

    if (table_type in ['db_time', 'db_count', 'iph_block_time']):
        action = 'blocked'

    elif (table_type in ['dv_time', 'dv_count', 'iph_view_time']):
        action = 'allowed'

    elif (table_type in ['ad_time', 'ad_count', 'iph_all_time']):
        action = 'all'

    #domains blocked, viewed, or both
    if (table_type in ['db_time', 'dv_time', 'ad_time']):
        return get_table_data(action, table='dnsproxy', method='last'), menu_option, '1'

    #domains blocked, viewed, or both
    elif (table_type in ['db_count', 'dv_count', 'ad_count']):
        return get_table_data(action, table='dnsproxy', method='top'), menu_option, '1'

    elif (table_type in ['iph_block_time', 'iph_view_time', 'iph_all_time']):
        return get_table_data(action=action, table='ipproxy', method='last'), menu_option, '2'

    elif (table_type in ['ips_time']):
        return get_table_data(action='all', table='ips', method='last'), menu_option, '3'

    elif (table_type in ['ic_all'] or 'i_client_remove' in form):

        # created function so load page could reuse code.
        return load_infected_clients()

def get_table_data(action, *, table, method, users=None):
    '''will query the database by using getattr(FirewallDB, f'query_{method}') on DB Connector context.
    this will return a max of 100 entries.'''
    with DBConnector() as FirewallDB:
        query_method = getattr(FirewallDB, f'query_{method}')
        table_data = query_method(100, table=table, action=action)

    return [format_row(row, users) for row in table_data]

def format_row(row, users):
    '''formats database data to be better displayed and managed by front end. will replace
    all '_' with ' '. If user is passed in, it will be appended before last_seen.'''
    Sys = System()

    *entries, last_seen = row

    ls_offset = Sys.calculate_time_offset(last_seen)
    last_seen = Sys.format_date_time(ls_offset)
    if (users is not None):
        entries.append(users.get(entries[0], {}).get('name', 'n/a'))

    entries.append(last_seen)
    return [str(x).lower().replace('_', ' ') for x in entries]

def load_infected_clients():
    dhcp_server = load_configuration('dhcp_server')
    users = dhcp_server['reservations']

    return get_table_data(action='all', table='infectedclients', method='last', users=users), '11', '4'