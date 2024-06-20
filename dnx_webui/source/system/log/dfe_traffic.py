#!/usr/bin/python3

from __future__ import annotations

import os

from typing import NamedTuple as _NamedTuple

from source.web_typing import web_module_import_callout

web_module_import_callout(__file__)

from dnx_gentools.def_constants import TYPE_CHECKING, HOME_DIR
from dnx_gentools.def_enums import DATA
from dnx_gentools.file_operations import tail_file

from source.web_validate import NO_STANDARD_ERROR
from source.web_interfaces import LogWebPage

if (TYPE_CHECKING):
    from source.web_typing import Optional
    from source.web_typing import Form, Args, WebLoadResponse, WebUpdateError


__all__ = ('WebPage',)

LOG_DIR = f'{HOME_DIR}/dnx_profile/log/traffic'
VALID_LOG_TYPES = [
    'firewall', '.nat',
]


class FIREWALL_LOG(_NamedTuple):
    timestamp: str
    type: str
    component: str
    rule: str
    action: str
    direction: str
    protocol: str
    in_intf: str
    src_zone: str
    src_country: str
    src_ip: str
    src_port: str
    out_intf: str
    dst_zone: str
    dst_country: str
    dst_ip: str
    dst_port: str


class WebPage(LogWebPage):
    '''
    available methods: load, update
    '''
    @staticmethod
    def load(form: Form, error: bool = None, uri_query: Optional[Args] = None) -> WebLoadResponse:

        # note: default table will only be hit when the page is first loaded.
        table_type = 'firewall' if error else form.get('table', 'firewall')
        table_data = [] if error else get_log_entries(f'{LOG_DIR}/{table_type}')

        return {
            'webui_tables': VALID_LOG_TYPES,
            'selected_webui_table': table_type,
            'table_data': table_data
        }

    @staticmethod
    def update(form: Form) -> WebUpdateError:
        table_type = form.get('table', DATA.MISSING)

        if (table_type is DATA.MISSING):
            return 1, 'Log type not specified.'

        if (table_type not in VALID_LOG_TYPES):
            return 2, f'Invalid log type -> {table_type}.'

        if table_type.startswith('.'):
            return 3, f'Log type [{table_type[1:]}] is unavailable at this time.'

        return NO_STANDARD_ERROR

def get_log_entries(file_path: str) -> list[FIREWALL_LOG]:
    log_files = reversed(sorted(os.listdir(file_path))[:-1])

    combined_raw = []
    for file in log_files:
        combined_raw.extend(tail_file(f'{file_path}/{file}', line_count=100))

        if len(combined_raw) >= 100:
            break

    # truncating last file to line limit
    combined_formatted = []
    combinedf_append = combined_formatted.append
    for entry in combined_raw[:100]:
        combinedf_append(FIREWALL_LOG(*[sub_entry.replace('"', '').split('=')[1] for sub_entry in entry.split()]))

    return combined_formatted
