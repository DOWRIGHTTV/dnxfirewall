#!/usr/bin/env python3

import os
from subprocess import Popen

if (os.geteuid() != 0):
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

if (not os.path.isdir('/home/dnx/dnxfirewall')):
    exit('dnxfirewall folder must be in /home/dnx directory to continue!')

print('updating user and folder permissions')
process = Popen('sudo usermod -aG www-data dnx', shell=True)
process.wait()
process = Popen('sudo usermod -aG dnx www-data', shell=True)
process.wait()
process = Popen('sudo chown -R dnx:dnx dnxfirewall', shell=True)
process.wait()

print('installing required python packages')
process = Popen('sudo mkdir /home/dnx/.local/bin', shell=True)
process.wait()
process = Popen('sudo -u dnx pip3 install flask pg8000 uwsgi', shell=True)
process.wait()
process = Popen('sudo pip3 install flask pg8000 uwsgi', shell=True)
process.wait()

print('copying dnx service files and enabling on startup')
services = [
    'log', 'syslog', 'database', 'dhcp-server', 'dns-proxy',
    'ip-proxy', 'ips', 'startup', 'updates', 'web', 'interface'
    ]
for service in services:
    process = Popen(f'sudo cp /home/dnx/dnxfirewall/services/dnx-{service}.service /etc/systemd/system/', shell=True)
    process.wait()
    process = Popen(f'sudo systemctl enable dnx-{service}', shell=True)
    process.wait()

print('generating ssl certificates')
process = Popen('sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/certs/dnx-web.key -out /etc/ssl/certs/dnx-web.crt', shell=True)
process.wait()

print('moving dnx_web configuration to nginx')
process = Popen('sudo mv /home/dnx/dnxfirewall/dnx_web /etc/nginx/sites-available/', shell=True)
process.wait()

print('enabling dnx frontend')
process = Popen('ln -s /etc/nginx/sites-available/dnx_web /etc/nginx/sites-enabled/', shell=True)
process.wait()
process = Popen('sudo rm /etc/nginx/sites-enabled/default')
process.wait()

print('creating default iptable rulesets')
process = Popen('sudo HOME_DIR=/home/dnx/dnxfirewall python3 /home/dnx/dnxfirewall/dnx_configure/dnx_iptables.py', shell=True)
process.wait()

print('DNX setup is complete! please restart the machine before continuing.')
print('navigate to dnx.firewall in browser to reach web interface')
print('default creds un: dnx | pw:firewall')