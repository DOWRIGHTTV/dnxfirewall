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

# FIXME: system logs are rendering with the file name letters enumerated on separate lines. im tired and jacked up my
#  eye up dinking around with a wire and cant see shit.

# NOTE: this will likely not be needed anymore with the ajax client implementation
def load_page(uri_query: Args) -> tuple[str, None, list[str]]:
    file_path = f'{HOME_DIR}/dnx_profile/log'

    return 'combined', None, get_log_entries(file_path)

def update_page(form: Form) -> tuple[str, None, list[str]]:
    log_table = form.get('table', 'combined')

    # ternary to handle initial page load.
    # TODO: this should be done better, but i am waiting until reports page gets converted to ajax to support both
    log_table = 'combined' if log_table == 'default' else log_table

    if (log_table not in LOG_FILES):
        return log_table, None, []

    # combined log is now a single file that reflects recent aggregated log at the time of loading
    file_path = LOG_DIR if log_table == 'combined' else f'{LOG_DIR}/{log_table}'

    # returning none to fill table_args var on the calling function to allow reuse with the report's page method
    return log_table, None, get_log_entries(file_path)

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
