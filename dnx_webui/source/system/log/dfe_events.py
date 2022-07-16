#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import DATA
from dnx_gentools.file_operations import load_data, config

from dnx_gentools.system_info import System
from source.web_validate import INVALID_FORM
from dnx_routines.database.ddb_connector_sqlite import DBConnector

def load_page(uri_query: Optional[dict] = None) -> tuple[list, str, str]:
    # if sent from the dashboard link, infected-clients table will open directly.
    if uri_query is not None and uri_query.get('view_clients', None):
        return load_infected_clients(), 'all', 'infected_clients'

    return get_table_data(action='all', table='dnsproxy', routine='last'), 'dns_proxy', 'all'

def update_page(form: dict) -> tuple[list, str, str]:

    # TODO: bring validation up to speed (ensure host is valid mac format). make database raise validation error
    #  when removing a client that isn't present in the db. this means some tomfoolery happened and we should return
    #  invalid form error.
    if ('i_client_remove' in form):
        ic_data = config(**{
            'client': form.get('infected_client', DATA.MISSING),
            'remote_host': form.get('detected_host', DATA.MISSING)
        })

        # TODO: investigate/fix this...
        if (DATA.MISSING in ic_data.values()):
            return INVALID_FORM

        with DBConnector() as FirewallDB:
            FirewallDB.execute('clear_infected', ic_data.client, ic_data.remote_host, table='infectedclients')

    # if form is invalid, will just resend default data for now.
    try:
        table_type, sort = form.get('table', DATA.MISSING).split('/')
    except:
        return load_page()

    if (sort not in ['last', 'top']):
        return load_page()

    action = form.get('menu', DATA.MISSING)
    if (action is DATA.MISSING):
        return load_page()

    # domains blocked, viewed, or both
    if (table_type in ['dns_proxy']):
        return get_table_data(action=action, table='dnsproxy', routine=sort), table_type, action

    elif (table_type in ['ip_proxy']):
        return get_table_data(action=action, table='ipproxy', routine=sort), table_type, action

    elif (table_type in ['intrusion_prevention']):
        return get_table_data(action='all', table='ips', routine=sort), table_type, action

    elif (table_type in ['infected_clients'] or 'i_client_remove' in form):

        # created function so load page could reuse code.
        return load_infected_clients(), 'infected_clients', 'all'

def get_table_data(*, action, table, routine, users=None):
    '''query the database by using getattr(FirewallDB, f'{method}') on DB Connector context.
    this will return a max of 100 entries.
    '''
    with DBConnector(readonly=True, connect=True) as firewall_db:
        table_data = firewall_db.execute(routine, 100, table=table, action=action)

    if (firewall_db.failed):
        return [['-', '-', '-', '-', '-', '-', '-']]

    return [format_row(row, users) for row in table_data]

def format_row(row: list, users: dict) -> list[str]:
    '''format database data to be better displayed and managed by frontend.

    will replace all '_' with spaces and append a username if available
    '''
    *entries, last_seen = row

    ls_offset = System.calculate_time_offset(last_seen)
    last_seen = System.format_date_time(ls_offset)

    if (users is not None):
        entries.append(users.get(entries[0], {}).get('name', 'n/a'))

    entries.append(last_seen)
    return [str(x).lower().replace('_', ' ') for x in entries]

def load_infected_clients() -> list:
    dhcp_server: dict = load_data('dhcp_server.cfg')
    users = dhcp_server['reservations']

    return get_table_data(action='all', table='infectedclients', routine='last', users=users)
