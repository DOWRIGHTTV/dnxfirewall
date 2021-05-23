#!/usr/bin/env python3

import os, sys
import time
import json

from subprocess import run, DEVNULL, CalledProcessError

USER_DIR = '/home/dnx'
HOME_DIR = f'{USER_DIR}/dnxfirewall'

os.environ['HOME_DIR'] = HOME_DIR
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_file_operations import ConfigurationManager
from dnx_configure.dnx_iptables import IPTableManager
from dnx_logging.log_main import LogHandler as Log

LOG_NAME = 'system'
PROGRESS_TOTAL_COUNT = 10

LINEBREAK = '-'*32

#----------------------------
# UTILS
#----------------------------

def sprint(string):
    '''setup print. includes timestamp before arg str.'''
    print(f'{round(time.time(), 2)}| {string}')

def eprint(string):
    '''error print. includes timestamp and alert before arg str.'''
    print(f'{round(time.time(), 2)}| !!! {string}')

    os._exit(1)

def dnx_run(string):
    '''convenience function, subprocess run wrapper adding additional args.'''
    try:
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

#----------------------------
# PROGRESS BAR
#----------------------------

# starting at -1 to compensate for first process
completed_count, p_total = -1, PROGRESS_TOTAL_COUNT
def progress(desc):
    global completed_count

    completed_count += 1

    bar_len = 32

    filled_len = int(round(bar_len * completed_count / float(p_total)))
    percents = round(100.0 * completed_count / float(p_total), 1)

    bar = ''.join(['#' * filled_len, '=' * (bar_len - filled_len)])
    sys.stdout.write(f'{completed_count}/{p_total} || [{bar}] {percents}% || {desc}{" "*12}\r')
    sys.stdout.flush()

#============================
# INTERFACE CONFIGURATION
#============================

# convenience function
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
    output = run('sudo ifconfig -a', shell=True, capture_output=True)

    interfaces_detected = []
    for line in output.stdout.decode('utf-8').splitlines():

        # used to detect first line of interface output
        if ('flags' in line):
            interface = line.split(':', 1)[0]

            # filtering loopback interface from user choices
            if (interface != 'lo'):
                interfaces_detected.append(interface)

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
        for i, int_name in enumerate(interface_config, 1):
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
        ('sudo apt install python3-pip -y', 'installing python3 package installer'),
        ('pip3 install flask uwsgi', 'installing python web app framework'),
        ('sudo apt install nginx -y', 'installing web server driver'),
        ('sudo apt install libnetfilter-queue-dev net-tools -y', 'installing networking components'),
        ('pip3 install Cython', 'installing C extension language (Cython)'),
        (f'sudo python3 {HOME_DIR}/utils/compile_bin_search.py build_ext --inplace', 'compiling binary search C extension'),
        (f'sudo python3 {HOME_DIR}/netfilter/setup.py build_ext --inplace', 'compiling python-netfilterqueue C extension')
    ]

    for command, desc in commands:

        progress(desc)

        dnx_run(command)

#============================
# PERMISSION CONFIGURATION
#============================
def set_permissions():

    progress('configuring dnxfirewall permissions')

    # set owner to dnx user/group
    dnx_run(f'sudo chown -R dnx:dnx {USER_DIR}/dnxfirewall')

    # apply file permissions 750 on folders, 640 on files
    dnx_run(f'sudo chmod -R 750 {USER_DIR}/dnxfirewall')
    dnx_run(f'sudo find {USER_DIR}/dnxfirewall -type f -print0|xargs -0 chmod 644')

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
    ignore_list = ['dnx-database-psql.service']

    progress('creating dnxfirewall services')

    services = os.listdir(f'{HOME_DIR}/services')
    for service in services:
        if (service in ignore_list): continue

        dnx_run(f'sudo cp {HOME_DIR}/services/{service} /etc/systemd/system/')

        dnx_run(f'sudo systemctl enable {service}')

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
    # pre checks to make prevent basic deployer failures
    check_run_as_root()
    check_dnx_user()
    check_clone_location()

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
    set_permissions()
    set_services()
    configure_iptables()

    mark_completion_flag()

    progress('dnxfirewall deployment complete')

    sprint('\nrestart then navigate to https://dnx.firewall to manage.')
    os._exit(0)

