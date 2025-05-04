#!/usr/bin/python3

from __future__ import annotations

import os

from source.web_typing import web_module_import_callout

web_module_import_callout(__file__)

from dnx_gentools.def_constants import TYPE_CHECKING, HOME_DIR
from dnx_gentools.def_enums import DATA
from dnx_gentools.file_operations import tail_file
from dnx_gentools.system_info import System

from source.web_validate import NO_STANDARD_ERROR
from source.web_interfaces import LogWebPage, WebAjaxContent

if (TYPE_CHECKING):
    from source.web_typing import Optional

    from source.web_typing import Form, Args, JSON, WebLoadResponse, WebUpdateError, WebAjaxResponse

    LOG_ENTRY = tuple[str, str, str, str]

__all__ = ('WebPage',)

LOG_DIR = f'{HOME_DIR}/dnx_profile/log'
VALID_LOG_TYPES = [
    'combined', 'dhcp_server', 'dns_proxy', 'ip_proxy', 'ips', 'logins', 'system', 'web_app',  # 'syslog',
]
class WebPage(LogWebPage):
    '''
    available methods: load, update, handle_ajax
    '''
    @staticmethod
    # NOTE: this will likely not be needed anymore with the ajax client implementation
    def load(form: Form, error: bool = False, uri_query: Optional[Args] = None) -> WebLoadResponse:
        return {
            'webui_tables': VALID_LOG_TYPES,
            'selected_webui_table': 'combined',
            'table_data': get_log_entries(LOG_DIR)
        }

    @staticmethod
    def update(form: Form) -> WebUpdateError:
        return NO_STANDARD_ERROR

    @staticmethod
    def handle_ajax(aform: JSON) -> WebAjaxResponse:
        table_type = aform.get('webui_table', DATA.MISSING)
        if (table_type is DATA.MISSING):
            return False, WebAjaxContent(error=1, message='Log type not specified.', data=[])

        elif (table_type not in VALID_LOG_TYPES):
            return False, WebAjaxContent(error=1, message=f'Invalid log type -> {table_type}.', data=[])

        # combined log is now a single file that reflects recent aggregated log at the time of loading
        file_path = LOG_DIR if table_type == 'combined' else f'{LOG_DIR}/{table_type}'

        return True, WebAjaxContent(error=0, message='Log data retrieved.', data=get_log_entries(file_path))

def get_log_entries(file_path: str) -> list[LOG_ENTRY]:
    log_files = reversed(sorted(os.listdir(file_path))[:-1])

    temp_logs = []
    for file in log_files:
        temp_logs.extend(tail_file(f'{file_path}/{file}', line_count=100))

        if len(temp_logs) >= 100:
            break

    combined_logs = []
    combined_logs_append = combined_logs.append
    for log_entry in temp_logs[:100]:

        # skipping over empty lines.
        if not log_entry.strip('\n'): continue

        epoch, *log_entry = log_entry.split('|', 3)
        date_time = System.calculate_time_offset(int(epoch))
        date_time = System.format_log_time(date_time)

        combined_logs_append((date_time, *log_entry))

    if (not combined_logs):
        combined_logs.append(('-', '-', '-', '-'))

    return combined_logs
