#!/usr/bin/env python3

import os
from subprocess import Popen

if (os.geteuid() != 0):
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

services = [
    'dns-proxy', 'ip-proxy', 'ips', 'dhcp-server', 'web',
    'updates', 'log', 'syslog', 'database', 'interface'
    ]

for service in services:
    Popen(f'sudo systemctl restart dnx-{service}', shell=True)
