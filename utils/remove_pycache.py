#!/usr/bin/env python3

import os

HOME_DIR = os.environ['HOME_DIR']

from subprocess import run, DEVNULL

if (os.geteuid() != 0):
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

folders = [
    'dnx_backups', 'dnx_configure',
    'dnx_database', 'dnx_frontend',
    'dnx_logging', 'dnx_system',
    'dhcp_server', 'ip_proxy'
    'dns_proxy', 'dnx_ips',
    'dnx_iptools', 'dnx_syslog',
    'dnx_netfilter'
    ]

removal_count = 0
for folder in folders:
    try:
        run(f'sudo rm -r {HOME_DIR}/{folder}/__pycache__', shell=True,
            stdout=DEVNULL, stderr=DEVNULL, check=True)
    except SubprocessError:
        pass
    else:
        removal_count += 1

print(f'pycache removed: {removal_count}')
