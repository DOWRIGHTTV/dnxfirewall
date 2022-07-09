#!/usr/bin/python3

from __future__ import annotations

import os

from source.web_typing import *

from dnx_gentools.def_constants import HOME_DIR
from dnx_gentools.file_operations import tail_file

LOG_DIR = f'{HOME_DIR}/dnx_system/log/traffic'
LOG_FILES = [
    'firewall', 'nat',
]

def load_page(form: Form) -> tuple[list[Optional[str]], str, None]:
    log_type: str = form.get('table', 'firewall')

    if (log_type not in LOG_FILES):
        return [], log_type, None

    # combined log is now a single file that reflects recent aggregated log at the time of loading
    file_path = f'{LOG_DIR}/{log_type}'

    # returning none to fill table_args var on the calling function to allow reuse with the report's page method
    return get_log_entries(file_path), log_type, None

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
