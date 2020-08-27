#!/usr/bin/env python3

import os
from subprocess import run, DEVNULL

if (os.geteuid() != 0):
    exit('You need to have root privileges to run this script.\nPlease try again, this time using "sudo". Exiting.')

if (not os.path.isdir('/home/dnx/dnxfirewall')):
    exit('dnxfirewall folder must be in /home/dnx directory to continue!')

print('updating user and folder permissions')
run('sudo usermod -aG www-data dnx', shell=True, stdout=DEVNULL)

run('sudo usermod -aG dnx www-data', shell=True, stdout=DEVNULL)

run('sudo chown -R dnx:dnx dnxfirewall', shell=True, stdout=DEVNULL)


print('installing required python packages')
run('sudo mkdir /home/dnx/.local/bin', shell=True, stdout=DEVNULL)

run('sudo -u dnx pip3 install flask pg8000 uwsgi', shell=True, stdout=DEVNULL)

run('sudo pip3 install flask pg8000 uwsgi', shell=True, stdout=DEVNULL)


print('copying dnx service files and enabling on startup')
services = [
    'log', 'syslog', 'dhcp-server', 'dns-proxy', 'ip-proxy',
    'ips', 'startup', 'web', 'interface'
    ]

for service in services:
    run(f'sudo cp /home/dnx/dnxfirewall/services/dnx-{service}.service /etc/systemd/system/', shell=True, stdout=DEVNULL)

    run(f'sudo systemctl enable dnx-{service}', shell=True, stdout=DEVNULL)
    
run(f'sudo cp /home/dnx/dnxfirewall/services/dnx-database-sqlite.service /etc/systemd/system/dnx-database.service', shell=True, stdout=DEVNULL)

print('generating ssl certificates')
run('sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/certs/dnx-web.key -out /etc/ssl/certs/dnx-web.crt', shell=True, stdout=DEVNULL)

print('moving dnx_web configuration to nginx')
run('sudo mv /home/dnx/dnxfirewall/dnx_web /etc/nginx/sites-available/', shell=True, stdout=DEVNULL)

print('enabling dnx frontend')
run('ln -s /etc/nginx/sites-available/dnx_web /etc/nginx/sites-enabled/', shell=True, stdout=DEVNULL)

run('sudo rm /etc/nginx/sites-enabled/default')

print('creating default iptable rulesets')
run('sudo HOME_DIR=/home/dnx/dnxfirewall python3 /home/dnx/dnxfirewall/dnx_configure/dnx_iptables.py', shell=True, stdout=DEVNULL)

print('DNX setup is complete! please restart the machine before continuing.')
print('navigate to dnx.firewall in browser to reach web interface')
print('default creds un: dnx | pw:firewall')
