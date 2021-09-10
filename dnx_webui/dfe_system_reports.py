#!/usr/bin/python3

import json
import sys, os, time

from flask import Flask, render_template, redirect, url_for, request, session

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import DATA
from dnx_sysmods.configure.file_operations import load_configuration
from dnx_sysmods.configure.system_info import Interface, System, Services
from dnx_sysmods.database.ddb_connector_sqlite import DBConnector

def load_page(uri_query=None):
    # if sent from dashboard link, infected clients table will open directly.
    if uri_query is not None and uri_query.get('view_clients', None):
        return load_infected_clients(), 'all', 'infected_clients'

    return get_table_data(action='all', table='dnsproxy', method='last'), 'dns_proxy', 'all'

def update_page(form):
    print(form)
    # TODO: bring validation up to speed (ensure host is valid mac format). make database raise validation error if the when removing
    # a client that isnt present in the db. this means some tomfoolery happened and we should return invalid form error.
    if ('i_client_remove' in form):
        infected_client = form.get('infected_client', None)
        detected_host = form.get('detected_host', None)
        if (not infected_client or not detected_host):
            return None # NOTE: should this be an error?

        with DBConnector() as FirewallDB:
            FirewallDB.infected_remove(infected_client, detected_host, table='infectedclients')

            FirewallDB.commit_entries()

    # if form is invalid, will just resend default data for now.
    try:
        table_type, sort = form.get('table', DATA.INVALID).split('/')
    except:
        return load_page()

    if (sort not in ['last', 'top']):
        return load_page()

    action = form.get('menu', DATA.INVALID)
    if (action is DATA.INVALID):
        return load_page()

    #domains blocked, viewed, or both
    if (table_type in ['dns_proxy']):
        return get_table_data(action, table='dnsproxy', method=sort), table_type, action # block or allow

    elif (table_type in ['ip_proxy']):
        return get_table_data(action=action, table='ipproxy', method=sort), table_type, action

    elif (table_type in ['intrusion_prevention']):
        return get_table_data(action='all', table='ips', method=sort), table_type, action

    elif (table_type in ['infected_clients'] or 'i_client_remove' in form):

        # created function so load page could reuse code.
        return load_infected_clients(), 'infected_clients', 'all'

def get_table_data(action, *, table, method, users=None):
    '''will query the database by using getattr(FirewallDB, f'query_{method}') on DB Connector context.
    this will return a max of 100 entries.'''
    with DBConnector() as FirewallDB:
        query_method = getattr(FirewallDB, f'query_{method}')
        table_data = query_method(100, table=table, action=action)

    # NOTE: this is code to make newer ip proxy categorization backwards compatible.
    ##############################################
    if (table == 'ipproxy'):
        table_data = [list(x) for x in table_data]
        for entry in table_data:
            if ('/' in entry[2]): continue

            entry[2] = '/'.join([entry[2], 'dnl'])
    ##############################################

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

    return get_table_data(action='all', table='infectedclients', method='last', users=users)
