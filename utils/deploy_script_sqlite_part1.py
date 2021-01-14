#!/usr/bin/env python3

import os
from subprocess import run, DEVNULL

if (os.geteuid() != 0):
    exit('You need to have root privileges to run this script.\nPlease try again, this time using "sudo". Exiting.')

print('creating firewall user')
run('sudo useradd -p firewall dnx && sudo mkdir /home/dnx && sudo chown dnx:dnx /home/dnx', shell=True, stdout=DEVNULL)

print('installing system dependencies')
run('sudo apt install nginx python3-pip libnetfilter-queue-dev -y', shell=True, stdout=DEVNULL)

print('enabling system services')
run('sudo systemctl enable nginx', shell=True, stdout=DEVNULL)

print('initial script complete. manual work required.')
print('step 1. configure lan interface with ip/subnet 192.168.83.1/24.')
print('step 2. move dnxfirewall folder into /home/dnx/.')
print('step 3. change data/config.json to show correct interface names.')
print('step 4. adjust sudoers to allow for some commmands to be done without password. see comments in file for what to add.')

# SUDOERS EDIT CODE
# sudo visudo

# no password | remove "#" for sudoer file
# dnx ALL = (root) NOPASSWD: /usr/sbin/iptables
# dnx ALL = (root) NOPASSWD: /usr/bin/systemctl
# dnx ALL = (root) NOPASSWD: /sbin/shutdown
# dnx ALL = (root) NOPASSWD: /sbin/reboot
