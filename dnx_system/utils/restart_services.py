#!/usr/bin/env python3

from __future__ import annotations

import os
from subprocess import run, DEVNULL

if (os.geteuid() != 0):
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

# 'syslog'
services = [
    'dns-proxy', 'ip-proxy', 'ips', 'dhcp-server', 'web',
    'log', 'database', 'interface'
    ]

for service in services:
    run(f'sudo systemctl restart dnx-{service}', shell=True, stdout=DEVNULL)
