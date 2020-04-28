#!/usr/bin/env python3

import os
from subprocess import run, DEVNULL, CalledProcessError

if (os.geteuid() != 0):
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

print('creating firewall user')
run('sudo useradd -p firewall dnx && sudo mkdir /home/dnx && sudo chown dnx:dnx /home/dnx', shell=True, stdout=DEVNULL)

print('installing system dependencies')
run('sudo apt install nginx postgresql python3-pip -y', shell=True, stdout=DEVNULL)

print('attempting install of libnetfilter_queue')
try:
    run('sudo apt install libnetfilter_queue -y', shell=True, check=True, stdout=DEVNULL)
except CalledProcessError:
    print('WARNING: unable to install kernel dependency. you are on your own. see https://netfilter.org/projects/libnetfilter_queue/doxygen/html/ for details.')

print('enabling system services')
services = ['nginx', 'postgresql']
for service in services:
    run(f'sudo systemctl enable {service}', shell=True, stdout=DEVNULL)

print('starting postgresql database service')
run('sudo systemctl start postgresql', shell=True, stdout=DEVNULL)

print('initial script complete. manual work required.')
print('step 1. please manually create database with following info. name:dnxfirewall user:dnx password:firewall.')
print('see the comments in this file for the commands to execute to achieve this.')
print('step 2. configure lan interface with ip/subnet 192.168.83.1/24.')
print('step 3. move dnxfirewall folder into /home/dnx/.')
print('step 4. change data/config.json to show correct interface names.')
print('step 5. adjust sudoers to allow for some commmands to be done without password. see comments in file for what to add.')

# DATABASE CREATION CODE

# sudo -u postgres psql
# CREATE DATABASE dnxfirewall;
# create user dnx with encrypted password 'firewall';
# grant all privileges on database dnxfirewall to dnx;

# SUDOERS EDIT CODE
# sudo visudo

# no password
# dnx ALL = (root) NOPASSWD: /usr/sbin/iptables
# dnx ALL = (root) NOPASSWD: /usr/bin/systemctl
# dnx ALL = (root) NOPASSWD: /sbin/shutdown
# dnx ALL = (root) NOPASSWD: /sbin/reboot
