#!/usr/bin/python3

import os, sys

HOME_DIR = os.environ.get('HOME_DIR', os.path.dirname(os.path.dirname((os.path.realpath('__file__')))))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.file_operations import tail_file
from dnx_sysmods.configure.system_info import System

# NOTE: this will likely not be needed anymore with ajax client implemented
def load_page(uri_query):
    file_path = f'{HOME_DIR}/dnx_system/log/combined'

    return get_log_entries(file_path), 'combined', None

def update_page(form):
    log_type = form.get('table', 'combined')

    # ternary to handle initial page load.
    # TODO: this should be done better, but i am waiting until reports page gets converted to ajax to support both
    log_type = 'combined' if log_type == 'default' else log_type

    if (log_type in ['combined', 'dhcp_server', 'dns_proxy', 'ip_proxy', 'ips', 'syslog', 'system', 'web_app', 'logins']):
        file_path = f'{HOME_DIR}/dnx_system/log/{log_type}'

    # returning none to fill the table_args var on the calling funtion to allow for reusablity with the reports page method
    # TODO: this should potentially be wrapped in error handling at main.
        # error will raise if table key is in form, but type is not in allowed list.
    return get_log_entries(file_path), log_type, None

# TODO: make front end logging 4 fields. date/time, service, level, entry. this will make the presentation nicer
# and will still allow for service identification on the combined system log.
    # NOTE: it looks like not all long entries, especially debug have the service identified in the log currently.
    # would probably be a good idea to just use the log/service name defined in module so each entry does not need
    # to worry about it.
def get_log_entries(file_path):
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
