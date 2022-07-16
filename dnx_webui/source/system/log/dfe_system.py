#!/usr/bin/python3

from __future__ import annotations

import os

from source.web_typing import *

from dnx_gentools.def_constants import HOME_DIR
from dnx_gentools.file_operations import tail_file
from dnx_gentools.system_info import System

LOG_DIR = f'{HOME_DIR}/dnx_profile/log'
LOG_FILES = [
    'combined', 'dhcp_server', 'dns_proxy', 'ip_proxy', 'ips', 'syslog', 'system', 'web_app', 'logins'
]

# NOTE: this will likely not be needed anymore with the ajax client implementation
def load_page(uri_query: Args) -> tuple[list[Optional[str]], str, None]:
    file_path = f'{HOME_DIR}/dnx_profile/log'

    return get_log_entries(file_path), 'combined', None

def update_page(form: Form) -> tuple[list[Optional[str]], str, None]:
    log_type = form.get('table', 'combined')

    # ternary to handle initial page load.
    # TODO: this should be done better, but i am waiting until reports page gets converted to ajax to support both
    log_type = 'combined' if log_type == 'default' else log_type

    if (log_type not in LOG_FILES):
        return [], log_type, None

    # combined log is now a single file that reflects recent aggregated log at the time of loading
    file_path = LOG_DIR if log_type == 'combined' else f'{LOG_DIR}/{log_type}'

    # returning none to fill table_args var on the calling function to allow reuse with the report's page method
    return get_log_entries(file_path), log_type, None

# TODO: make front end logging 4 fields. date/time, service, level, entry. this will make the presentation nicer
#  and will still allow for service identification on the combined system log.
    # NOTE: it looks like not all long entries, especially debug have the service identified in the log currently.
    # would probably be a good idea to just use the log/service name defined in module so each entry does not need
    # to worry about it.
def get_log_entries(file_path: str) -> list[str]:
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

    return combined_logs
