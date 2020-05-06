#!/usr/bin/env python3

import os
from subprocess import run, DEVNULL

if (os.geteuid() != 0):
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

if not os.path.isdir('/home/dnx/dnxfirewall'):
    exit('dnxfirewall folder must be in /home/dnx directory to continue!')

print('updating user and folder permissions')
run('sudo chown -R dnx:dnx dnxfirewall', shell=True, stdout=DEVNULL)

print('installing required python packages')
run('sudo mkdir /home/dnx/.local/bin', shell=True, stdout=DEVNULL)

run('sudo -u dnx pip3 install flask pg8000 uwsgi', shell=True, stdout=DEVNULL)

run('sudo pip3 install flask pg8000 uwsgi', shell=True, stdout=DEVNULL)

print('copying dnx service files and enabling on startup')
services = [
    'log', 'database', 'dhcp-server', 'dns-proxy',
    'ip-proxy', 'ips', 'syslog', 'startup', 'interface'
    ]

for service in services:
    run(f'sudo cp /home/dnx/dnxfirewall/services/dnx-{service}.service /etc/systemd/system/', shell=True, stdout=DEVNULL)

    if (service =! 'syslog'):
        run(f'sudo systemctl enable dnx-{service}', shell=True, stdout=DEVNULL)

print('creating default iptable rulesets')
run('sudo HOME_DIR=/home/dnx/dnxfirewall python3 /home/dnx/dnxfirewall/dnx_configure/dnx_iptables.py', shell=True, stdout=DEVNULL)

print('DNX setup is complete! all services will start on system restart.')
