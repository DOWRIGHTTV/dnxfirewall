#!/usr/bin/python3

import os, sys

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_file_operations import tail_file
from dnx_configure.dnx_system_info import System

def load_page():
    file_path = f'{HOME_DIR}/dnx_system/log/combined'

    log_files = [f'{file_path}/{file}' for file in reversed(os.listdir(file_path)[-7:])]

    return get_log_entries(log_files)

def update_page(form):
    log_type = form.get('table', 'combined')
    if (log_type in ['combined', 'dhcp_server', 'dns_proxy', 'ip_proxy', 'ips', 'syslog', 'system', 'update', 'logins']):
        file_path = f'{HOME_DIR}/dnx_system/log/{log_type}'
        log_files = [f'{file_path}/{file}' for file in reversed(os.listdir(file_path)[-7:])]

    selected = {
        'combined': '1', 'system': '2', 'update': '3', 'logins': '4',
        'dns_proxy': '5', 'ip_proxy': '6', 'ips': '7', 'dhcp_server':'8' ,
        'syslog': '9'}.get(log_type, '1')

    # returning none to fill the table_args var on the calling funtion to allow for reusablity with the reports page method
    return get_log_entries(log_files), selected, None

def get_log_entries(log_files):
    combined_log = []
    total_lines, line_limit = 0, 100
    for file in log_files:
        if (file.endswith('temp')): continue

        log_entries = tail_file(file, line_count=100)
        for line in log_entries:
            total_lines += 1
            if total_lines >= line_limit: break

            epoch, log_message = line.split('|')
            date_time = System.calculate_time_offset(int(epoch))
            date_time = System.format_log_time(date_time)

            combined_log.append((date_time, log_message))

    return combined_log