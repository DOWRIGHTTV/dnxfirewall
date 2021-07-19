#!/usr/bin/env python3

import os, sys
import time
import json
import socket

from subprocess import run, DEVNULL, CalledProcessError

USER_DIR = '/home/dnx'
HOME_DIR = f'{USER_DIR}/dnxfirewall'

os.environ['HOME_DIR'] = HOME_DIR
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import str_join
from dnx_configure.dnx_file_operations import ConfigurationManager
from dnx_configure.dnx_iptables import IPTableManager
from dnx_logging.log_main import LogHandler as Log

LOG_NAME = 'system'
PROGRESS_TOTAL_COUNT = 12

LINEBREAK = '-'*32

VERBOSE = False

# DID: use socket.if_nameindex() for interface identification and assignment, replace net-tools + subprocess

#----------------------------
# UTILS
#----------------------------

def sprint(string):
    '''setup print. includes timestamp before arg str.'''
    print(f'{time.strftime("%H:%M:%S")}| {string}')

def eprint(string):
    '''error print. includes timestamp and alert before arg str.'''
    print(f'{time.strftime("%H:%M:%S")}| !!! {string}')

    os._exit(1)

def dnx_run(string):
    '''convenience function, subprocess run wrapper adding additional args.'''
    try:
        if (VERBOSE):
            run(string, shell=True, check=True)

        else:
            run(string, shell=True, stdout=DEVNULL, stderr=DEVNULL, check=True)

    except CalledProcessError as cpe:
        eprint(cpe)

def check_run_as_root():
    if (os.getuid()):

        eprint('must run dnxfirewall auto loader as root. exiting...')

def check_dnx_user():
    with open('/etc/passwd') as passwd:
        passwd = passwd.read().splitlines()

    if not any([usr for usr in passwd if usr.split(':', 1)[0] == 'dnx']):

        eprint('dnx user does not exist. create user and clone repo into dnx home directory before running.')

def check_clone_location():
    if (not os.path.isdir(HOME_DIR)):

        eprint('dnxfirewall filesystem must be located at /home/dnx.')

def check_already_ran():
    with ConfigurationManager('config') as dnx:
        dnx_settings = dnx.load_configuration()['settings']

    if (dnx_settings['auto_loader']):

        eprint('dnxfirewall auto loader has already been completed. exiting...')

# installing net tools if not already present
# def check_net_tools():
#     dnx_run('sudo apt install net-tools -y', 'installing net-tools')

#----------------------------
# PROGRESS BAR
#----------------------------

# starting at -1 to compensate for first process
completed_count, p_total = -1, PROGRESS_TOTAL_COUNT
def progress(desc):
    global completed_count

    completed_count += 1

    bar_len = 30

    filled_len = int(round(bar_len * completed_count / float(p_total)))
    percents = round(100.0 * completed_count / float(p_total), 1)

    bar = str_join(['#' * filled_len, '=' * (bar_len - filled_len)])
    sys.stdout.write(f'{" "*90}\r')
    sys.stdout.write(f'{completed_count}/{p_total} || [{bar}] {percents}% || {desc}\r')
    sys.stdout.flush()

#============================
# INTERFACE CONFIGURATION
#============================

# convenience function wrapper for phsysical interface to dnxfirewall zone association.
def configure_interfaces():
    with open(f'{HOME_DIR}/utils/intf_config.json', 'r') as intf_configs:
        intf_configs = intf_configs.read()

    interfaces_detected = check_system_interfaces()

    user_intf_config = collect_interface_associations(interfaces_detected)

    for intf_name, intf in user_intf_config.items():
            intf_configs = intf_configs.replace(f'_{intf_name}_', intf)

    write_net_config(intf_configs.replace('    ', '  '))

    set_dnx_interfaces(user_intf_config)

    set_dhcp_interfaces(user_intf_config)

def check_system_interfaces():

    interfaces_detected = [intf[1] for intf in socket.if_nameindex() if 'lo' not in intf[1]]

    # output = run('sudo ifconfig -a', shell=True, capture_output=True)

    # interfaces_detected = []
    # for line in output.stdout.decode('utf-8').splitlines():

    #     # used to detect first line of interface output
    #     if ('flags' in line):
    #         interface = line.split(':', 1)[0]

    #         # filtering loopback interface from user choices
    #         if (interface != 'lo'):
    #             interfaces_detected.append(interface)

    if (len(interfaces_detected) < 3):
        eprint(f'at least 3 interfaces are required to deploy dnxfirewall. detected: {len(interfaces_detected)}.')

    return interfaces_detected

def collect_interface_associations(interfaces_detected):
    print(LINEBREAK)
    print('available interfaces')
    print(LINEBREAK)

    for i, interface in enumerate(interfaces_detected, 1):
        print(f'{i}. {interface}')

    print(LINEBREAK)

    # build out full json for interface configs as dict
    interface_config = {'WAN': None, 'LAN': None, 'DMZ': None}
    while True:
        for int_name in interface_config:
            while True:
                select = input(f'select {int_name} interface: ')
                if (select.isdigit() and int(select) in range(1, len(interfaces_detected)+1)):
                    interface_config[int_name] = interfaces_detected[int(select)-1]
                    break

        if confirm_interfaces(interface_config):
            if len(set(interface_config.values())) == 3:
                break

            eprint('interface definitions must be unique.')

    return interface_config

# takes interface config as dict, converts to yaml, then writes to system folder
def write_net_config(interface_config):
    sprint('configuring netplan service...')
    # print(interface_config)
    str_replacement = ['{', '}', '"', ',']
    for s in str_replacement:
        interface_config = interface_config.replace(s, '')

    yaml_output = [y for y in interface_config.splitlines() if y.strip()]

    # write config file to netplan
    # print(yaml_output)
    with open('/etc/netplan/01-dnx-interfaces.yaml', 'w') as intf_config:
        intf_config.write('\n'.join(yaml_output))

# modifying dnx configuration files with user specified interface names and their corresponding zones
def set_dnx_interfaces(user_intf_config):
    sprint('setting dnx interface configurations...')
    with ConfigurationManager('config') as dnx:
        dnx_settings = dnx.load_configuration()

        interface_settings = dnx_settings['settings']['interfaces']

        for zone, intf  in user_intf_config.items():
            interface_settings[zone.lower()]['ident'] = intf

        dnx.write_configuration(dnx_settings)

def set_dhcp_interfaces(user_intf_config):
    with ConfigurationManager('dhcp_server') as dhcp:
        dhcp_settings = dhcp.load_configuration()

        interface_settings = dhcp_settings['dhcp_server']['interfaces']

        for zone in ['LAN', 'DMZ']:

            interface_settings[zone.lower()]['ident'] = user_intf_config[zone]

        dhcp.write_configuration(dhcp_settings)

def confirm_interfaces(interface_config):
    print(' '.join([f'{zone}={intf}' for zone, intf in interface_config.items()]))
    while True:
        answer = input('confirm? [Y/n]: ')
        if (answer.lower() in ['y', '']):
            return True

        else:
            return False

#============================
# INSTALL PACKAGES
#============================

def install_packages():

    commands = [
        ('sudo apt install python3-pip -y', 'setting up python3'),
#        ('sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 0', None),
#        ('sudo update-alternatives --set python3 /usr/bin/python3.8', None),
        ('pip3 install flask uwsgi', 'installing python web app framework'),
        ('sudo apt install nginx -y', 'installing web server driver'),
        ('sudo apt install libnetfilter-queue-dev -y', 'installing networking components'),
        ('pip3 install Cython', 'installing C extension language (Cython)')
    ]

    for command, desc in commands:

        progress(desc)

        dnx_run(command)

def compile_extensions():

    commands = [
        (f'sudo python3 {HOME_DIR}/utils/compile_bin_search.py build_ext --inplace', 'compiling binary search C extension'),
        (f'sudo python3 {HOME_DIR}/netfilter/setup.py build_ext --inplace', 'compiling python-netfilterqueue C extension')
    ]

    for command, desc in commands:

        progress(desc)

        dnx_run(command)

def configure_webui():
    cert_subject = str_join([
        '/C=US',
        '/ST=Arizona',
        '/L=cyberspace',
        '/O=dnxfirewall',
        '/OU=security',
        '/CN=dnx.firewall',
        '/emailAddress=help@dnxfirewall.com'
    ])

    generate_cert_commands = [
        f'sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048',
        f'-keyout {HOME_DIR}/dnx_system/ssl/dnx-web.key',
        f'-out {HOME_DIR}/dnx_system/ssl/dnx-web.crt',
        f'-subj {cert_subject}'
    ]

    commands = [
        (' '.join(generate_cert_commands), 'generating dnx webui ssl certificate'),
        (f'sudo cp {HOME_DIR}/utils/dnx_web /etc/nginx/sites-available/', 'configuring management webui'),
        ('ln -s /etc/nginx/sites-available/dnx_web /etc/nginx/sites-enabled/', None),
        ('sudo rm /etc/nginx/sites-enabled/default', None)
    ]

    for command, desc in commands:

        # this allows some commands to ride off of the previous status message and completion %.
        if (desc):
            progress(desc)

        dnx_run(command)

#============================
# PERMISSION CONFIGURATION
#============================

def set_permissions():

    progress('configuring dnxfirewall permissions')

    # creating database file here so it can get its permissions modified. This will
    # ensure it wont be overriden by update pulls.
    dnx_run(f'touch {HOME_DIR}/dnx_system/data/dnxfirewall.sqlite3')

    # set owner to dnx user/group
    dnx_run(f'sudo chown -R dnx:dnx {USER_DIR}/dnxfirewall')

    # apply file permissions 750 on folders, 640 on files
    dnx_run(f'sudo chmod -R 750 {USER_DIR}/dnxfirewall')
    dnx_run(f'sudo find {USER_DIR}/dnxfirewall -type f -print0|xargs -0 chmod 640')

    # adding www-data user to dnx group
    dnx_run('sudo usermod -aG dnx www-data')

    # reverse of above
    dnx_run('sudo usermod -aG www-data dnx')

    # update sudoers to allow dnx user no pass for specific system functions
    no_pass = [
        'dnx ALL = (root) NOPASSWD: /usr/sbin/iptables-restore',
        'dnx ALL = (root) NOPASSWD: /usr/sbin/iptables',
        'dnx ALL = (root) NOPASSWD: /usr/bin/systemctl',
        'dnx ALL = (root) NOPASSWD: /sbin/shutdown',
        'dnx ALL = (root) NOPASSWD: /sbin/reboot'
    ]

    for line in no_pass:
        dnx_run(f'echo "{line}" | sudo EDITOR="tee -a" visudo')

#============================
# SERVICE FILE SETUP
#============================

def set_services():
    ignore_list = ['dnx-database-psql.service', 'dnx-syslog.service']

    progress('creating dnxfirewall services')

    services = os.listdir(f'{HOME_DIR}/services')
    for service in services:
        if (service in ignore_list): continue

        dnx_run(f'sudo cp {HOME_DIR}/services/{service} /etc/systemd/system/')

        dnx_run(f'sudo systemctl enable {service}')

    dnx_run(f'sudo systemctl enable nginx')

#============================
# INITIAL IPTABLE SETUP
#============================

def configure_iptables():
    progress('loading default iptables')

    with IPTableManager() as iptables:
        iptables.apply_defaults(suppress=True)

#============================
# CLEANUP
#============================

def mark_completion_flag():
    with ConfigurationManager('config') as dnx:
        dnx_settings = dnx.load_configuration()

        dnx_settings['settings']['auto_loader'] = True

        dnx.write_configuration(dnx_settings)

if __name__ == '__main__':
    # pre checks to make sure application can run properly
    check_run_as_root()
    check_dnx_user()
    check_clone_location()
    # check_net_tools()

    # intiializing log module which is required when using ConfigurationManager
    Log.run(
        name=LOG_NAME
    )
    ConfigurationManager.set_log_reference(Log)

    check_already_ran()

    configure_interfaces()

    sprint('starting system deployment...')
    print(LINEBREAK)

    install_packages()
    compile_extensions()
    configure_webui()
    set_permissions()
    set_services()
    configure_iptables()

    mark_completion_flag()

    progress('dnxfirewall deployment complete')

    sprint('\nrestart system then navigate to https://dnx.firewall from LAN or DMZ to manage.')
    sprint('ssh is allowed on WAN for setup. This should be removed prior to moving to production.')
    os._exit(0)
