#!/usr/bin/env python3

from __future__ import annotations

from source.web_typing import web_module_import_callout

web_module_import_callout(__file__)

from dnx_gentools.def_constants import TYPE_CHECKING
from dnx_gentools.def_enums import DATA
from dnx_gentools.file_operations import ConfigurationError, load_data, config
from dnx_gentools.system_info import System

from dnx_routines.database import DBConnector

from source.web_validate import *
from source.web_interfaces import LogWebPage

if (TYPE_CHECKING):
    from source.web_typing import *


__all__ = ('WebPage',)

DB_TABLE_LOOKUP = {
    'dns_proxy': 'dnsproxy',
    'ip_proxy': 'ipproxy',
    'intrusion_prevention': 'ips',
    'infected_clients': 'infected_clients'
}.get

VALID_WEBUI_TABLES = ['dns_proxy', 'ip_proxy', 'intrusion_prevention', 'infected_clients']
VALID_DROPDOWN_FILTERS = ['all', 'blocked', 'allowed']


class WebPage(LogWebPage):
    '''
    available methods: load, update
    '''
    @staticmethod
    def load(form: Form, error: bool = False, uri_query: Optional[Args] = None) -> WebLoadResponse:

        # direct page load (form won't be present) or page submission has an error will set webui_table to default.
        # note: when ajax is applied to page form submission, the default will be the only option returned here.
        if (error or not form):
            table_type, dropdown_filter, sort = 'dns_proxy', 'all', 'last'

        # if sent from the dashboard link, infected-clients table will open directly.
        elif uri_query.get('view_clients'):
            table_type, dropdown_filter, sort = 'infected_clients', 'all', 'last'

        else:
            table_type, dropdown_filter, sort = form.get('webui_table').split('/')

        return {
            'webui_tables': VALID_WEBUI_TABLES,
            'dropdown_filters': VALID_DROPDOWN_FILTERS,
            'selected_webui_table': table_type,
            'dropdown_filter': dropdown_filter,
            'table_data': get_table_data(action=dropdown_filter, table=DB_TABLE_LOOKUP(table_type), routine=sort)
        }

    @staticmethod
    def update(form: Form) -> WebUpdateError:

        vbtn = form.get('vbtn', DATA.MISSING)

        if (vbtn == 'change_view'):
            try:
                table_type, dropdown_filter, sort = form.get('webui_table', DATA.MISSING).split('/')
            except:
                return 1, 'Invalid table, dropdown-filter, and sort type format.'

            if (table_type not in VALID_WEBUI_TABLES):
                return 2, 'Invalid table type.'

            if (dropdown_filter not in VALID_DROPDOWN_FILTERS):
                return 3, 'Invalid dropdown filter.'

            if (sort not in ['last', 'top']):
                return 4, 'Invalid Sort type specified.'

        elif (vbtn == 'inf_client_remove'):
            ic_rh = form.get('inf_client_remove', DATA.MISSING)
            if (ic_rh is DATA.MISSING):
                return 11, 'Client and remote host not specified.'

            try:
                inf_client, detected_host = ic_rh.split(',')
            except ValueError:
                return 12, 'Invalid client or remote host.'

            # todo: validate inf_client ip address
            #    -: validate detected_host mac address

            with DBConnector() as FirewallDB:
                FirewallDB.execute('clear_infected', inf_client, detected_host, table='infectedclients')

        else:
            return 99, INVALID_FORM

        return NO_STANDARD_ERROR

def get_table_data(*, action, table, routine, users=None) -> list[list[str]]:
    '''query the database by using getattr(FirewallDB, f'{method}') on DB Connector context.
    this will return a max of 100 entries.
    '''
    if (table == 'error'):
        return [['-', '-', '-', '-', '-', '-', '-']]

    with DBConnector(readonly=True, connect=True) as firewall_db:
        table_data = firewall_db.execute(routine, 100, table=table, action=action)

    if (firewall_db.failed or not table_data):
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

# todo: this should be reworked to use the name in the dhcp lease instead of reservations.
# def load_infected_clients() -> list:
#     dhcp_server: dict = load_data('dhcp_server.cfg', cfg_type='system/global')
#     users = dhcp_server['reservations']
#
#     return get_table_data(action='all', table='infectedclients', routine='last', users=users)
