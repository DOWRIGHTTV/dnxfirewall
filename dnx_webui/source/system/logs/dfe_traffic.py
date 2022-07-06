#!/usr/bin/python3

from __future__ import annotations

import os

from source.web_typing import *

from dnx_gentools.def_constants import HOME_DIR
from dnx_gentools.file_operations import tail_file

LOG_DIR = f'{HOME_DIR}/dnx_system/logs/traffic'
LOG_FILES = [
    'firewall', 'nat',
]

def load_page(form: Form) -> tuple[list[Optional[str]], str, None]:
    log_type: str = form.get('table', 'firewall')

    if (log_type not in LOG_FILES):
        return [], log_type, None

    # combined log is now a single file that reflects recent aggregated logs at the time of loading
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

    combined_logs = []
    for file in log_files:
        combined_logs.extend(tail_file(f'{file_path}/{file}', line_count=100))

        if len(combined_logs) >= 100:
            break

    # truncating last file to line limit
    combined_logs = combined_logs[:100]

    return combined_logs
