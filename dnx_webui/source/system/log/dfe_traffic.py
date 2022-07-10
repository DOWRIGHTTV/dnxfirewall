#!/usr/bin/python3

from __future__ import annotations

import os

from typing import NamedTuple as _NamedTuple

from source.web_typing import *

from dnx_gentools.def_constants import HOME_DIR
from dnx_gentools.file_operations import tail_file

LOG_DIR = f'{HOME_DIR}/dnx_system/log/traffic'
LOG_FILES = [
    'firewall', 'nat',
]

class FIREWALL_LOG(_NamedTuple):
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

def load_page(form: Form) -> tuple[list[FIREWALL_LOG], str, None]:
    log_type: str = form.get('table', 'firewall')

    if (log_type not in LOG_FILES):
        return [], log_type, None

    # combined log is now a single file that reflects recent aggregated log at the time of loading
    file_path = f'{LOG_DIR}/{log_type}'

    # returning none to fill table_args var on the calling function to allow reuse with the report's page method
    return get_log_entries(file_path), log_type, None

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
        print([sub_entry for sub_entry in entry.split()])
        combinedf_append(FIREWALL_LOG(*[sub_entry.replace('"', '').split('=') for sub_entry in entry.split()][1]))

    return combined_formatted
