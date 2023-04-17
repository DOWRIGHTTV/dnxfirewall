#!/usr/bin/env python3

from __future__ import annotations

import os
import sys
import time
import json
import socket
import readline

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional
from functools import partial
from subprocess import run as _run, DEVNULL, CalledProcessError

from dnx_gentools.def_constants import HOME_DIR, INITIALIZE_MODULE, hardout, str_join
from dnx_gentools.file_operations import ConfigurationManager, load_data, write_configuration, json_to_yaml

from dnx_iptools.iptables import IPTablesManager
from dnx_routines.logging.log_client import Log

from dnx_cli.utils.shell_colors import text

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.file_operations import ConfigChain


ERROR_SHOW_TIME = .33

srun = partial(_run, shell=True, check=True)
def lprint(sep: str = '-'): print(text.lightblue(f'{sep}' * 80))

# ===============
# BANNER
# ===============
BANNER = text.lightblue('\n'.join([
    ' ____  _   ___  __     _   _   _ _____ ___  _     ___    _    ____  _____ ____',
    '|  _ \| \ | \ \/ /    / \ | | | |_   _/ _ \| |   / _ \  / \  |  _ \| ____|  _ \ ',
    '| | | |  \| |\  /    / _ \| | | | | || | | | |  | | | |/ _ \ | | | |  _| | |_) |',
    '| |_| | |\  |/  \   / ___ \ |_| | | || |_| | |__| |_| / ___ \| |_| | |___|  _ <',
    '|____/|_| \_/_/\_\ /_/   \_\___/  |_| \___/|_____\___/_/   \_\____/|_____|_| \_\ '
]))

@dataclass
class Args:
    v: int = 0
    verbose: int = 0
    packages: int = 0
    iptables: int = 0

    _update: int = 0

    @property
    def verbose_set(self):
        return self.v or self.verbose


LOG_NAME: str = 'system'
PROGRESS_TOTAL_COUNT: int = 1  # set permissions count added here

LINEBREAK: str = text.lightblue('-' * 32)

SYSTEM_DIR:  str = 'dnx_profile'
UTILITY_DIR: str = 'dnx_profile/utils'

# ----------------------------
# UTILS
# ----------------------------
def flash_input_error(error: str, space_ct: int) -> None:
    # moves cursor up one space in the terminal
    sys.stdout.write('\033[1A')

    sys.stdout.write(f'\033[{space_ct}C')
    sys.stdout.write(text.orange(f'{error}\r', style=None))

    time.sleep(ERROR_SHOW_TIME)

    sys.stdout.write(f'{" " * os.get_terminal_size().columns}\r')

def sprint(s: str, /) -> None:
    '''setup print. includes timestamp before arg str.

    the passed in message will be automatically colorized.
    '''
    print(text.lightgrey(f'{time.strftime("%H:%M:%S")}| ') + text.yellow(f'{s}'))

def eprint(s: str, /) -> None:
    '''error print. includes timestamp and alert before arg str.

    the passed in message will not be automatically colorized. this should be handled by the caller.
    '''
    while True:
        sys.stdout.write(text.lightgrey(f'{time.strftime("%H:%M:%S")}| ') + text.red(f'!!! {s} '))
        answer: str = input(
            text.lightgrey('continue? [y/', style=None) +
            text.lightblue('N') +
            text.lightgrey(']: ', style=None)
        )
        if (answer.lower() == 'y'):
            return

        elif (answer.lower() in ['n', '']):
            sprint(text.red('exiting...'))
            hardout()

        else:
            flash_input_error('invalid selection', 13 + len(s))  # length of raw text

def dnx_run(s: str, /) -> None:
    '''convenience function, subprocess run wrapper adding additional args.
    '''
    try:
        if (args.verbose_set):
            srun(s)

        else:
            srun(s, stdout=DEVNULL, stderr=DEVNULL)

    except CalledProcessError as cpe:
        eprint(f'{cpe}')

def check_run_as_root() -> None:
    if (os.getuid()):
        eprint(
            text.yellow('dnxfirewall auto loader requires') +
            text.red('root') +
            text.yellow('permissions.')
        )

def check_dnx_user() -> None:
    with open('/etc/passwd', 'r') as passwd_f:
        passwd: list[str] = passwd_f.read().splitlines()

    if not any([usr for usr in passwd if usr.split(':', 1)[0] == 'dnx']):
        eprint(
            text.green('dnx ') +
            text.yellow('user does ') +
            text.red('not ') +
            text.yellow('exist. create user and clone repo into dnx home directory before running.')
        )

def check_clone_location() -> None:

    if (not os.path.isdir(HOME_DIR)):
        eprint(
            text.yellow('dnxfirewall filesystem ') +
            text.red('must ') +
            text.yellow('be located at /home/dnx.')
        )

def check_already_ran() -> None:
    with ConfigurationManager('system', cfg_type='global') as dnx:
        dnx_settings: ConfigChain = dnx.load_configuration()

    if (not args._update_system and dnx_settings['auto_loader']):
        eprint(
            text.red('dnxfirewall has already been installed.')
        )

    elif (args._update_system and not dnx_settings['auto_loader']):
        eprint(
             text.red('dnxfirewall has not been installed. see readme for guidance.')
        )

def set_branch() -> None:
    available_branches = ['development', 'stable']

    lprint()
    print(text.yellow('available branches'))
    lprint()

    print(text.yellow('1. development'))
    print(text.yellow('2. stable'))

    lprint()

    question = 'branch selection: '
    while True:
        selection: str = input(question)
        if (selection.isdigit() and int(selection) in (1, 2)):
            break

        flash_input_error('invalid selection', len(question))

    with ConfigurationManager('system', cfg_type='global') as dnx:
        dnx_settings: ConfigChain = dnx.load_configuration()

        dnx_settings['branch'] = available_branches[int(selection) - 1]

        dnx.write_configuration(dnx_settings.expanded_user_data)

# ----------------------------
# PROGRESS BAR
# ----------------------------
def clear_line() -> None:
    '''clears the current line in the terminal.

        useful for writes that are not on a new line to prevent previous character overflow.
    '''
    sys.stdout.write(' ' * os.get_terminal_size().columns + '\r')

    sys.stdout.flush()


# starting at -1 to compensate for the first process. todo: (we arent though....)
bar_len: int = 30
completed_count: int = 0
def progress(desc: str, *, completed: Optional[int] = None, total: Optional[int] = None) -> None:
    '''prints a progress bar to the terminal.

    if complete and total are not passed in, the global completed_count and PROGRESS_TOTAL_COUNT will be used.
    '''
    global completed_count

    if (completed is None and total is None):
        completed = completed_count
        total = PROGRESS_TOTAL_COUNT

    # this will ensure completed count does not exceed total count when rendering.
    # this would only happen if I miscalculated the total count somewhere. (happens too often LOL :/)
    if (completed > total):
        completed = total

    # calculating bar %
    ratio: float = completed / total
    filled_len: int = int(bar_len * ratio)

    # COLORIZING COMPLETION STATUS BAR
    # --------------------------------------------------------------------
    bar: str
    if (ratio < .34):
        bar = text.red('#' * filled_len, style=None)
        completed = text.red(f'{int(100 * ratio)}'.rjust(2), style=None)

    elif (ratio < .67):
        bar = text.orange('#' * filled_len, style=None)
        completed = text.orange(f'{int(100 * ratio)}', style=None)

    else:
        bar = text.green('#' * filled_len, style=None)
        completed = text.yellow(f'{int(100 * ratio)}', style=None)

    if (ratio >= 1):
        completed = text.green(f'{int(100 * ratio)}', style=None)

    bar += text.lightgrey('=' * (bar_len - filled_len))

    # RENDERING UPDATED TIMESTAMP, BAR, DESCRIPTION
    # --------------------------------------------------------------------
    clear_line()

    sys.stdout.write(text.lightgrey(f'{time.strftime("%H:%M:%S")}| '))
    sys.stdout.write(text.yellow(f'{completed}', style=None) + text.lightgrey(f'/{total} |'))
    sys.stdout.write(
        text.lightgrey(f'| [', style=None) + bar + text.lightgrey(f'] ', style=None) +
        completed + text.lightgrey('% |', style=None)
    )
    sys.stdout.write(text.yellow(f'| {desc}\r'))

    # allows for rendering bar without moving the completion %.
    if (desc):
        completed_count += 1

    # prevents bar from being overwritten once complete
    if (filled_len == bar_len):
        sys.stdout.write('\n')

    # forces current stdout buffer to be written to terminal
    sys.stdout.flush()


# ============================
# INTERFACE CONFIGURATION
# ============================
# convenience function wrapper for physical interface to dnxfirewall zone association.
def configure_interfaces() -> None:
    interfaces_detected: list[str] = check_system_interfaces()

    user_intf_config: dict[str, str] = collect_interface_associations(interfaces_detected)
    public_dns_servers: dict = load_data('dns_server.cfg', cfg_type='system/global')['resolvers']

    set_dnx_interfaces(user_intf_config)
    set_dhcp_interfaces(user_intf_config)

    with open(f'{SYSTEM_DIR}/interfaces/intf_config_template.cfg', 'r') as intf_configs_f:
        intf_configs: str = intf_configs_f.read()

    for intf_name, intf in user_intf_config.items():
        intf_configs = intf_configs.replace(f'_{intf_name}_', intf)

    # storing the modified template containing specified interface names.
    # this will be used to configure wan interface via webui or change system level dns servers.
    # note: json.loads is needed because the write function expects a python dictionary.
    write_configuration(json.loads(intf_configs), 'interfaces', filepath=f'{SYSTEM_DIR}/interfaces')

    # setting public dns servers on the interface so the system itself will use the user-configured servers.
    dns1: str = public_dns_servers['primary']['ip_address']
    dns2: str = public_dns_servers['secondary']['ip_address']

    yaml_output: str = json_to_yaml(intf_configs, is_string=True)
    yaml_output = yaml_output.replace('_PRIMARY__SECONDARY_', f'{dns1},{dns2}')

    write_net_config(yaml_output)

def check_system_interfaces() -> list[str]:
    interfaces_detected = [intf[1] for intf in socket.if_nameindex() if 'lo' not in intf[1]]

    if (len(interfaces_detected) < 3):
        eprint(
            text.yellow('minimum ') +
            text.red('3 ') +
            text.yellow(f'interfaces are required to deploy dnxfirewall. detected: {len(interfaces_detected)}.')
        )

    return interfaces_detected

def collect_interface_associations(interfaces_detected: list[str]) -> dict[str, str]:
    lprint()
    print(text.yellow('available interfaces'))
    lprint()

    for i, interface in enumerate(interfaces_detected, 1):
        print(text.yellow(f'{i}. {interface}'))

    lprint()

    # build out full json for interface configs as dict
    interface_config: dict[str, str] = {'WAN': '', 'LAN': '', 'DMZ': ''}
    while True:
        for int_name in interface_config:
            while True:
                select = input(f'select {text.yellow(int_name)} interface: ')
                if (select.isdigit() and int(select) in range(1, len(interfaces_detected)+1)):
                    interface_config[int_name] = interfaces_detected[int(select)-1]
                    break

                flash_input_error('invalid selection', 18)

        if confirm_interfaces(interface_config):
            if (len(set(interface_config.values())) == 3):
                break

            eprint(text.yellow('interface definitions must be unique.'))

    return interface_config

# takes interface config as dict, converts to yaml, then writes to system folder
def write_net_config(interface_configs: str) -> None:
    sprint('configuring netplan service...')

    # write config file to netplan
    with open('/etc/netplan/01-dnx-interfaces.yaml', 'w') as intf_config:
        intf_config.write(interface_configs)

    # removing the default configuration set during os install.
    try:
        os.remove('/etc/netplan/00-installer-config.yaml')
    except:
        pass

# modifying dnx configuration files with the user specified interface names and their corresponding zones
def set_dnx_interfaces(user_intf_config: dict[str, str]) -> None:
    sprint('configuring dnxfirewall network interfaces...')

    with ConfigurationManager('system', cfg_type='global') as dnx:
        dnx_settings: ConfigChain = dnx.load_configuration()

        for zone, intf in user_intf_config.items():
            dnx_settings[f'interfaces->builtin->{zone.lower()}->ident'] = intf

        dnx.write_configuration(dnx_settings.expanded_user_data)

def set_dhcp_interfaces(user_intf_config: dict[str, str]) -> None:
    with ConfigurationManager('dhcp_server', cfg_type='global') as dhcp:
        dhcp_settings: ConfigChain = dhcp.load_configuration()

        for zone in ['LAN', 'DMZ']:

            dhcp_settings[f'interfaces->builtin->{zone.lower()}->ident'] = user_intf_config[zone]

        dhcp.write_configuration(dhcp_settings.expanded_user_data)

def confirm_interfaces(interface_config: dict[str, str]) -> bool:
    print(' '.join([f'{zone}={text.yellow(intf)}' for zone, intf in interface_config.items()]))
    while True:
        answer: str = input(
            text.lightgrey('confirm? [', style=None) +
            text.lightblue('Y') +
            text.lightgrey('/n]: ', style=None)
        )
        if (answer.lower() in ['y', '']):
            return True

        elif (answer.lower() == 'n'):
            return False

        flash_input_error('invalid selection', 18)


# ============================
# BUILD LIBRARIES
# ============================
def build_libraries(*, count_only: bool = False) -> None:
    global PROGRESS_TOTAL_COUNT

    # NOTE: this needs to be updated as libs get added to this function
    if (count_only):
        PROGRESS_TOTAL_COUNT += 3

        return

    libraries = [
        (f'{SYSTEM_DIR}/libraries/libmnl', [
            (f'bash configure', 'building netfilter mnl (lib)'),
            (f'make', None),
            (f'sudo make install', None)
        ]),
        (f'{SYSTEM_DIR}/libraries/libnetfilter_queue', [
            (f'bash configure', 'building netfilter queue (lib)'),
            (f'make', None),
            (f'sudo make install', None)
        ])
    ]

    for libdir, commands in libraries:

        os.chdir(libdir)
        for command, desc in commands:
            if (desc):
                progress(desc)

            dnx_run(command)

        os.chdir(HOME_DIR)

    # libnetfilter_conntrack will be installed via package manager for now.
    progress('building netfilter conntrack (lib)')
    dnx_run('sudo apt install libnetfilter-conntrack-dev')

# ============================
# INSTALL PACKAGES
# ============================
def install_packages() -> list:

    commands = [
        # required system dependencies for building dnxfirewall
        ('sudo apt install autoconf build-essential libnfnetlink-dev -y', 'installing system dependencies'),

        ('sudo apt install nginx -y', 'installing web server driver'),
        ('sudo apt install net-tools -y', 'installing networking components'),

        ('sudo apt install python3-pip -y', 'setting up python3'),
        ('pip3 install flask uwsgi', 'installing python web app framework'),
        ('pip3 install Cython', 'installing C extension language (Cython)')
    ]

    return commands

# this is a no op if already on configured branch, but we will use it to return branch name also.
def checkout_configured_branch() -> str:
    configured_branch: str = load_data('system.cfg', cfg_type='global', filepath=f'{SYSTEM_DIR}/data/usr')['branch']

    branch_name = 'dnxfirewall-dev' if configured_branch == 'development' else 'dnxfirewall'

    dnx_run(f'git checkout {branch_name}')

    return branch_name

def update_local_branch(branch: str) -> list[tuple]:

    commands: list[tuple[str, str]] = [
        ('git stash', None),  # resetting any local changes before pulling
        (f'git pull origin {branch}', 'downloading updates')
    ]

    return commands

def compile_extensions(*, count_only: bool = False) -> Optional[list[tuple]]:
    global PROGRESS_TOTAL_COUNT

    commands: list[tuple[str, str]] = [
        ('sudo python3 dnx_run.py compile cprotocol-tools _autoloader_', 'compiling cprotocol tools'),
        ('sudo python3 dnx_run.py compile dnx-nfqueue _autoloader_', 'compiling dnx-nfqueue'),
        ('sudo python3 dnx_run.py compile hash-trie _autoloader_', 'compiling dnx-hash_trie'),
        ('sudo python3 dnx_run.py compile cfirewall _autoloader_', 'compiling cfirewall'),
    ]

    # incrementing progress total count to ensure progress bar is accurate
    if (count_only):
        PROGRESS_TOTAL_COUNT += len(commands)

        return

    return commands

def configure_webui() -> list[tuple]:
    cert_subject: str = str_join([
        '/C=US',
        '/ST=Arizona',
        '/L=cyberspace',
        '/O=dnxfirewall',
        '/OU=security',
        '/CN=dnx.rules',
        '/emailAddress=help@dnxfirewall.com'
    ])

    generate_cert_commands: str = ' '.join([
        'sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048',
        f'-keyout {SYSTEM_DIR}/ssl/dnx-web.key',
        f'-out {SYSTEM_DIR}/ssl/dnx-web.crt',
        f'-subj {cert_subject}'
    ])

    commands: list[tuple[str, Optional[str]]] = [
        (generate_cert_commands, 'generating dnx webui ssl certificate'),
        (f'sudo cp -n {UTILITY_DIR}/dnx_web /etc/nginx/sites-available/', 'configuring management webui'),
        ('ln -fs /etc/nginx/sites-available/dnx_web /etc/nginx/sites-enabled/', None),
        ('sudo rm -f /etc/nginx/sites-enabled/default', None)
    ]

    return commands


# ============================
# PERMISSION CONFIGURATION
# ============================
def set_permissions() -> None:

    progress('configuring dnxfirewall permissions')

    commands: list[str] = [

        # creating database file here, so it can get its permissions modified.
        # this will also ensure it won't be overridden by update pulls.
        f'touch {SYSTEM_DIR}/data/dnxfirewall.sqlite3',

        # set the dnx filesystem owner to the dnx user/group
        f'chown -R dnx:dnx {HOME_DIR}',

        # apply file permissions 750 on folders, 640 on files
        f'chmod -R 750 {HOME_DIR}',
        f'find {HOME_DIR} -type f -print0|xargs -0 chmod 640',

        # setting the dnx command line utility as executable
        f'chmod 750 dnx_run.py',

        # creating symlink to allow dnx command from anywhere if logged in as dnx user
        f'ln -fs {HOME_DIR}/dnx_run.py /usr/local/bin/dnx',

        # adding www-data user to dnx group
        'usermod -aG dnx www-data',

        # reverse of above
        'usermod -aG www-data dnx'
    ]

    for command in commands:
        dnx_run(command)

    # testing sudoer file as a precaution. if this fails, the build itself is bad.
    # this should never happen, but humans make mistakes, so at least this will not brick the system if root wasn't
    # set with a password.
    try:
        srun(f'sudo visudo -cf {SYSTEM_DIR}/admin/dnx', stderr=DEVNULL, stdout=DEVNULL)
    except CalledProcessError:
        hardout(
            text.lightgrey(f'{time.strftime("%H:%M:%S")}| ') +
            text.red('!!! sudoer file syntax error. cannot continue. exiting...')
        )

    # configure sudoers.d to allow dnx user "no-pass" for specific system functions
    dnx_run(f'sudo cp -n {SYSTEM_DIR}/admin/dnx /etc/sudoers.d/')

def set_signature_permissions() -> None:
    commands: list[str] = [
        # set the dnx filesystem owner to the dnx user/group
        f'chown -R dnx:dnx {HOME_DIR}/dnx_profile/signatures',

        # apply file permissions 750 on folders, 640 on files
        f'chmod -R 750 {HOME_DIR}/dnx_profile/signatures',
        f'find {HOME_DIR}/dnx_profile/signatures -type f -print0|xargs -0 chmod 640'
    ]

    for command in commands:
        dnx_run(command)

# ============================
# SERVICE FILE SETUP
# ============================
def set_services() -> None:
    ignore_list = ['dnx-syslog.service']

    progress('creating dnxfirewall services')

    services = os.listdir(f'{UTILITY_DIR}/services')
    for service in services:

        if (service not in ignore_list):

            dnx_run(f'cp -n {UTILITY_DIR}/services/{service} /etc/systemd/system/')
            dnx_run(f'systemctl enable {service}')

    dnx_run(f'systemctl enable nginx')


# ============================
# INITIAL IPTABLES SETUP
# ============================
def configure_iptables() -> None:
    progress('loading default iptables')

    with IPTablesManager() as iptables:
        iptables.apply_defaults(suppress=True)


# ============================
# CLEANUP
# ============================
def mark_completion_flag() -> None:
    with ConfigurationManager('system', cfg_type='global') as dnx:
        dnx_settings: ConfigChain = dnx.load_configuration()

        dnx_settings['auto_loader'] = True

        dnx.write_configuration(dnx_settings.expanded_user_data)

# TODO: add code to pull mac from wan interface and set it in the config file stored in the usr dir.
def store_default_mac():
    pass

def signature_update(system_update: bool = False) -> None:
    import dnx_control.system.signature_update as signature_update

    sprint('security signature updater initiated.')
    # ===========================================
    # INITIAL FILE CHECKSUM INFORMATION DOWNLOAD
    # ===========================================
    sprint('downloading initial file integrity information from remote server.')
    file_validations: list[tuple] = []
    for attempt in range(1, 4):
        if file_validations := signature_update.get_file_validations():
            break

        eprint(f'unable to download file validation information. tries: {attempt}/3')

    else:
        sprint(f'retry limit reached.')
        hardout('try again later. exiting...')

    # ===========================================
    # REMOTE SIGNATURE VERSION INFORMATION
    # ===========================================
    sprint('looking up remote signature version for compatibility.')
    remote_version = 99991231
    rsv_name, rsv_hash = file_validations[0]
    for attempt in range(1, 4):

        error, remote_version = signature_update.get_remote_version(rsv_name)
        if (not error):

            if signature_update.validate_file_download(f'{rsv_name}_TEMP', rsv_hash):
                break

        eprint(f'unable to validate signature versioning information. tries: {attempt}/3')

    else:
        sprint(f'retry limit reached. check connection and try again later.')
        hardout('exiting...')

    # system update will ignore the signature version check and force the update.
    if not signature_update.compare_signature_version(remote_version, system_update=True):
        hardout('a system update is required to support the latest signature sets.')

    # ===========================================
    # REMOTE SIGNATURE MANIFEST
    # ===========================================
    sprint('downloading remote signature manifest.')
    manifest = []
    rsm_name, rsm_hash = file_validations[1]
    for attempt in range(1, 4):

        # downloading manifest of signature files to be downloaded.
        manifest = signature_update.get_remote_signature_manifest(rsm_name)
        if (manifest):

            if signature_update.validate_file_download(f'{rsm_name}_TEMP', rsm_hash):
                break

        eprint(f'unable to validate remote signature manifest. tries: {attempt}/3')

    else:
        sprint(f'retry limit reached. check connection and try again later.')
        hardout('exiting...')

    sprint(f'done. {len(manifest)} signature files will be downloaded.')

    # LIST FILES CONTAINED IN MANIFEST
    # if (args.verbose_set):
    #     for i, f in enumerate(manifest, 1):
    #         sprint(f'{i}. {f[0]} - {f[1]}')

    download_failure_list = []
    checksum_failure_list = []

    for attempt in range(3):

        success = 0
        # retries only need to download the files that are remaining
        # converting to set to remove duplicates
        if (attempt > 0):
            progress('incomplete', completed=success, total=len(manifest))
            eprint(f'({len(checksum_failure_list)}) signature download errors detected. tries: {attempt}/3')

            manifest = list({*download_failure_list, *checksum_failure_list})

            download_failure_list.clear()
            checksum_failure_list.clear()

        for file, checksum in manifest:

            progress(f'downloading {file}', completed=success, total=len(manifest))

            # downloading signatures and running checksum validation.
            if not signature_update.download_signature_file(file):
                download_failure_list.append((file, checksum))
                # if (args.verbose_set):
                #     sprint(f'download failed for {file}')

            else:
                check_passed = signature_update.validate_signature_file(file, checksum)
                if (not check_passed):
                    checksum_failure_list.append((file, checksum))

                else:
                    success += 1
                    # if (args.verbose_set):
                    #     sprint(f'checksum failed for {file}')

        if (not download_failure_list and not checksum_failure_list):
            progress('done', completed=success, total=len(manifest))
            sprint('all signatures downloaded successfully. installing...')
            break

    # will give the user the option to load the signatures that downloaded successfully or exit.
    else:
        sprint(f'retry limit reached.')
        sprint(f'{len(download_failure_list)} signatures failed to download.')
        sprint(f'{len(checksum_failure_list)} signatures failed checksum validation.')

    # settings the flag to identify a file move in progress or partial signature update.
    if not signature_update.set_signature_update_flag():
        eprint('signature update may already be in in progress or a previous update was interrupted.')

        signature_update.set_signature_update_flag(override=True)

    signature_update.move_signature_files(manifest, checksum_failure_list)

    sprint('signatures installed. setting permissions.')

    # probably not needed, but doing anyway for consistency.
    set_signature_permissions()

    signature_update.clear_signature_update_flag()

    final_msg = 'signature update complete.'

    if (not system_update):
        final_msg += ' the security modules must be restarted for the changes to take effect.'

    sprint(final_msg)

def run():
    global PROGRESS_TOTAL_COUNT

    # will relative paths beyond HOME_DIR
    os.chdir(HOME_DIR)

    # signature updates are handled separately from the rest of the build process unless the system is being updated.
    if (args._update_signatures):
        signature_update()

        return

    if (not args._update_system):
        PROGRESS_TOTAL_COUNT += 1  # copying service files
        set_branch()
        configure_interfaces()

    if (not args._update_system) and (args._update_system and args.iptables):
        PROGRESS_TOTAL_COUNT += 1  # building iptables

    # will hold all dynamically set commands prior to execution to get an accurate count for progress bar.
    dynamic_commands: list[tuple[str, Optional[str]]] = []

    branch = checkout_configured_branch()

    if (args._update_system):
        dynamic_commands.extend(update_local_branch(branch))

    # packages will be installed during initial installation automatically.
    # if update is set, the default is to not update packages.
    if (not args._update_system) or (args._update_system and args.packages):
        dynamic_commands.extend(install_packages())

    if (not args._update_system):
        dynamic_commands.extend(configure_webui())

    compile_extensions(count_only=True)

    PROGRESS_TOTAL_COUNT += len([1 for k, v in dynamic_commands if v])

    action = 'update' if args._update else 'deployment'
    sprint(f'starting dnxfirewall {action}...')
    lprint()

    # NOTE: ensuring the progress bar count is properly reflected.
    if (not args._update_system):
        build_libraries(count_only=True)

    progress('')  # this will render 0% bar, so we don't need to use offsets.
    for command, desc in dynamic_commands:

        if (desc):
            progress(desc)

        dnx_run(command)

    # building netfilter libs from source.
    # keeping this separate from packages since we cannot guarantee the user distro's versioning meets the minimum
    # requirements [source is locally contained within dnxfirewall repo].
    if (not args._update_system):
        build_libraries()

    # this must be done after the netfilter libs are built.
    for command, desc in compile_extensions():

        if (desc):
            progress(desc)

        dnx_run(command)

    if (not args._update_system) or (args._update_system and args.iptables):
        configure_iptables()

    set_permissions()

    if (not args._update_system):
        set_services()
        mark_completion_flag()

    progress('dnxfirewall installation complete...')

    # signatures will be updated during initial installation or system update automatically.
    signature_update(system_update=True)

    sprint('control of the WAN interface configuration has been taken by dnxfirewall.')
    sprint('use the webui to configure a static ip or enable ssh access if needed.')
    sprint('restart the system then navigate to https://192.168.83.1 from LAN to manage.')

    hardout()


if INITIALIZE_MODULE('autoloader'):
    print(BANNER)

    # stripping "-" will allow standard syntax args to be accepted
    try:
        args = Args(**{a.lstrip('-'): 1 for a in os.environ['PASSTHROUGH_ARGS'].split(',') if a})
    except Exception as E:
        hardout(f'DNXFIREWALL arg parse failure => {E}')

    args._update_system = 1 if os.environ.get('_SYSTEM_UPDATE') else 0
    args._update_signatures = 1 if os.environ.get('_SIGNATURE_UPDATE') else 0

    # pre-checks to make sure application can run properly
    check_run_as_root()
    check_dnx_user()
    check_clone_location()

    # initializing log module which is required when using ConfigurationManager
    Log.run(name=LOG_NAME, suppress_output=True)
    ConfigurationManager.set_log_reference(Log)

    if (not args._update_signatures):
        # this uses the config manager, so must be called after log initialization
        check_already_ran()
