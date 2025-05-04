#!/usr/bin/env python3

from __future__ import annotations

import os
import time
import socket
import readline

from dataclasses import dataclass
from subprocess import CalledProcessError

from dnx_gentools.def_exceptions import hardout
from dnx_gentools.def_constants import TYPE_CHECKING, HOME_DIR, INITIALIZE_MODULE, str_join
from dnx_gentools.file_operations import ConfigurationManager, json_to_yaml
from dnx_gentools.file_operations import write_file, load_data, write_data, change_file_owner

from dnx_iptools.iptables import IPTablesManager

from dnx_routines.logging.log_client import Log

from dnx_cli.utils.shell_colors import text
from dnx_cli.utils.io import dnx_run, dnx_run_v, flash_input_error, title_print, line_print, ts_print, err_print
from dnx_cli.utils.ux import create_progress_bar

# todo: rework this module to hot reload if the file was changed/updated within the current update session.
#  - this includes not using hardout() directly and raises a SystemExit exception instead.

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Optional
    from dnx_gentools.def_typing import SIGNATURE_MANIFEST, bint

    from dnx_gentools.file_operations import ConfigChain

# ===============
# BANNER
# ===============
BANNER = text.lightblue('\n'.join([
    '.__ .  .\  /.___._..__ .___.  ..__..   .   ',
    '|  \|\ | >< [__  | [__)[__ |  |[__]|   |   ',
    '|__/| \|/  \|   _|_|  \[___|/\||  ||___|___',
]))

@dataclass
class Args:
    v: bint = 0
    verbose: bint = 0
    packages: bint = 0
    iptables: bint = 0

    force: bint = 0  # only applies to signature updates at this time

    _update_system: bint = 0
    _update_signatures: bint = 0

    @property
    def verbose_set(self):
        return self.v or self.verbose

# ----------------------------
# UTILS
# ----------------------------
def shell_run(s: str, /) -> None:
    '''convenience function, subprocess run wrapper adding additional args.
    '''
    try:
        if (args.verbose_set):
            dnx_run_v(s, shell=True)

        else:
            dnx_run(s, shell=True)

    except CalledProcessError as cpe:
        err_print(f'{cpe}')

def check_run_as_root() -> None:
    if (os.getuid()):
        err_print(
            text.yellow('dnxfirewall auto loader requires') +
            text.red('root') +
            text.yellow('permissions.')
        )

def check_dnx_user() -> None:
    with open('/etc/passwd', 'r') as passwd_f:
        passwd: list[str] = passwd_f.read().splitlines()

    if not any([usr for usr in passwd if usr.split(':', 1)[0] == 'dnx']):
        err_print(
            text.green('dnx ') +
            text.yellow('user does ') +
            text.red('not ') +
            text.yellow('exist. create user and clone repo into dnx home directory before running.')
        )

def check_clone_location() -> None:

    if (not os.path.isdir(HOME_DIR)):
        err_print(
            text.yellow('dnxfirewall filesystem ') +
            text.red('must ') +
            text.yellow('be located at /home/dnx.')
        )

def check_already_ran() -> None:
    with ConfigurationManager('system', cfg_type='global') as dnx:
        dnx_settings: ConfigChain = dnx.load_configuration()

    if (not args._update_system and dnx_settings['auto_loader']):
        err_print(
            text.red('dnxfirewall has already been installed.')
        )

    elif (args._update_system and not dnx_settings['auto_loader']):
        err_print(
             text.red('dnxfirewall has not been installed. see readme for guidance.')
        )

def set_branch() -> None:
    available_branches = ['development', 'stable']

    title_print(text.yellow('available branches'))

    print(text.yellow('1. development'))
    print(text.yellow('2. stable'))

    line_print()

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

# ============================
# INTERFACE CONFIGURATION
# ============================
intf_templates = {
    'WAN': {
        'optional': 'yes',
        'dhcp4': 'yes',
        'dhcp4-overrides': {
            'use-dns': 'false'
        },
        'nameservers': {
            'addresses': '[_PRIMARY__SECONDARY_]'
        },
        'routes': '[]'
    },
    'LAN': {
        'optional': 'yes',
        'addresses': '[192.168.83.1/24]',
        'routes': '[]'
    },
    'DMZ': {
        'optional': 'yes',
        'addresses': '[192.168.84.1/24]',
        'routes': '[]'
    }
}
# convenience function wrapper for physical interface to dnxfirewall zone association.
def configure_interfaces() -> None:
    intf_mode, interfaces_detected = get_system_interfaces()

    user_intf_config: dict[str, str] = get_interface_associations(intf_mode, interfaces_detected)

    public_dns_servers: dict = load_data('dns_server.cfg', cfg_type='system/global')['resolvers']

    set_dnx_interfaces(user_intf_config)
    set_dhcp_interfaces(user_intf_config)

    intf_configs = {"network": {"version": 2, "ethernets": {}}}
    for intf_name, intf in user_intf_config.items():

        intf_configs['network']['ethernets'][intf] = intf_templates[intf_name]

        # setting public dns servers on the interface so the system itself will use the user-configured servers.
        if (intf_name == 'WAN'):
            dns1: str = public_dns_servers['primary']['ip_address']
            dns2: str = public_dns_servers['secondary']['ip_address']

            intf_configs['network']['ethernets'][intf]['nameservers']['addresses'] = f'[{dns1},{dns2}]'

    # NOTE: this is partially refactored. once the interface patch is complete, this will likely not be necessary.
    # storing the modified template containing specified interface names.
    # this will be used to configure wan interface via webui or change system level dns servers.
    intf_yaml = json_to_yaml(intf_configs)
    write_file(f'{SYSTEM_DIR}/interfaces.yaml', intf_yaml)

    write_net_config(intf_yaml)

def get_system_interfaces() -> tuple[str, list[str]]:
    interfaces_detected = [intf[1] for intf in socket.if_nameindex() if 'lo' not in intf[1]]
    intf_mode = 'full'

    if (not interfaces_detected):
        hardout(
            text.red('no network interfaces detected. exiting...')
        )

    if (len(interfaces_detected) == 1):
        intf_mode = 'local'
        err_print(
            text.yellow('only ') +
            text.red('1 ') +
            text.yellow('interface detected. the system will run in local only mode until an additional interface is set.')
        )

    elif (len(interfaces_detected) == 2):
        intf_mode = 'no-dmz'
        err_print(
            text.yellow('only ') +
            text.red('2 ') +
            text.yellow('interfaces detected. the system will run in no-dmz mode until an additional interface is set.')
        )

    return intf_mode, interfaces_detected

def get_interface_associations(intf_mode, interfaces_detected: list[str]) -> dict[str, str]:
    title_print(text.yellow('available interfaces'))

    for i, interface in enumerate(interfaces_detected, 1):
        print(text.yellow(f'{i}. {interface}'))

    line_print()

    interface_config: dict[str, str] = {'LAN': ''}
    if (intf_mode == 'no-dmz'):
        interface_config['WAN'] = ''

    elif (intf_mode == 'full'):
        interface_config['WAN'] = ''
        interface_config['DMZ'] = ''

    # build out full json for interface configs as dict
    selections = set()
    while True:
        for int_name in interface_config:
            while True:
                try:
                    select = int(input(f'select {text.yellow(int_name)} interface: '))

                    if (select not in selections):
                        interface_config[int_name] = interfaces_detected[select - 1]

                        break

                    flash_input_error('interface already selected', 18)
                except:
                    flash_input_error('invalid selection', 18)

        if confirm_interfaces(interface_config):
            break

    return interface_config

# takes interface config as dict, converts to yaml, then writes to system folder
def write_net_config(interface_configs: str) -> None:
    ts_print('configuring netplan service...')

    # write config file to netplan
    with open('/etc/netplan/01-dnx-interfaces.yaml', 'w') as intf_config:
        intf_config.write(interface_configs)

    # removing the default configuration set during os install.
    try:
        os.remove('/etc/netplan/00-installer-config.yaml')
    except FileNotFoundError:
        pass

# modifying dnx configuration files with the user specified interface names and their corresponding zones
def set_dnx_interfaces(user_intf_config: dict[str, str]) -> None:
    ts_print('configuring dnxfirewall network interfaces...')

    with ConfigurationManager('system', cfg_type='global') as dnx:
        dnx_settings: ConfigChain = dnx.load_configuration()

        for zone, intf in user_intf_config.items():
            dnx_settings[f'interfaces->builtin->{zone.lower()}->ident'] = intf

        dnx.write_configuration(dnx_settings.expanded_user_data)

def set_dhcp_interfaces(user_intf_config: dict[str, str]) -> None:
    with ConfigurationManager('dhcp_server', cfg_type='global') as dhcp:
        dhcp_settings: ConfigChain = dhcp.load_configuration()

        for zone, intf in user_intf_config.items():

            if (zone == 'WAN'):
                continue

            dhcp_settings[f'interfaces->builtin->{zone.lower()}->ident'] = intf

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
# TODO: make sure the lib dir for libraries is in $PATH, if not add it.
#   - alternatively can create a sim link in cfirewall then include that dir in the cython compile script.
#   - note: it is currently specified as a libdir in the compiling script.
def build_libraries(*, count_only: bool = False) -> None:
    global NUMBER_OF_IU_TASKS

    # NOTE: this needs to be updated as libs get added to this function
    if (count_only):
        NUMBER_OF_IU_TASKS += 3

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
                system_iu_progress(desc)

            shell_run(command)

        os.chdir(HOME_DIR)

    # libnetfilter_conntrack will be installed via package manager for now.
    system_iu_progress('building netfilter conntrack (lib)')
    shell_run('sudo apt install libnetfilter-conntrack-dev')

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

    shell_run(f'git checkout {branch_name}')

    return branch_name

def update_local_branch(branch: str) -> list[tuple[str, Optional[str]]]:

    commands: list[tuple[str, str]] = [
        ('git stash', None),  # resetting any local changes before pulling
        (f'git pull origin {branch} --force', 'downloading updates')
    ]

    return commands

def compile_extensions(*, count_only: bool = False) -> Optional[list[tuple]]:
    global NUMBER_OF_IU_TASKS

    commands: list[tuple[str, str]] = [
        ('sudo python3 dnx_run.py compile cprotocol-tools _autoloader_', 'compiling cprotocol tools'),
        ('sudo python3 dnx_run.py compile dnx-nfqueue _autoloader_', 'compiling dnx-nfqueue'),
        ('sudo python3 dnx_run.py compile hash-trie _autoloader_', 'compiling dnx-hash_trie'),
        ('sudo python3 dnx_run.py compile cfirewall _autoloader_', 'compiling cfirewall'),
    ]

    # incrementing progress total count to ensure the progress bar is accurate
    if (count_only):
        NUMBER_OF_IU_TASKS += len(commands)

        return

    return commands

def configure_webui() -> list[tuple[str, Optional[str]]]:
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

    system_iu_progress('configuring dnxfirewall permissions')

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
        shell_run(command)

    # testing sudoer file as a precaution. if this fails, the build itself is bad.
    # this should never happen, but humans make mistakes, so at least this will not brick the system if root wasn't
    # set with a password.
    try:
        shell_run(f'sudo visudo -cf {SYSTEM_DIR}/admin/dnx')
    except CalledProcessError:
        hardout(
            text.lightgrey(f'{time.strftime("%H:%M:%S")}| ') +
            text.red('!!! sudoer file syntax error. cannot continue. exiting...')
        )

    # configure sudoers.d to allow dnx user "no-pass" for specific system functions
    shell_run(f'sudo cp -n {SYSTEM_DIR}/admin/dnx /etc/sudoers.d/')

def set_signature_permissions() -> None:
    commands: list[str] = [
        # set the dnx filesystem owner to the dnx user/group
        f'chown -R dnx:dnx {HOME_DIR}/dnx_profile/signatures',

        # apply file permissions 750 on folders, 640 on files
        f'chmod -R 750 {HOME_DIR}/dnx_profile/signatures',
        f'find {HOME_DIR}/dnx_profile/signatures -type f -print0|xargs -0 chmod 640'
    ]

    for command in commands:
        shell_run(command)

# ============================
# SERVICE FILE SETUP
# ============================
# todo: add check to to diff the installed vs local file to reduce unnecessary copies.
#  - if all are the same, we can skip the daemon-reload.
def set_services(update: bint = 0) -> None:
    ignore_list = ['dnx-syslog.service']

    action = 'updating' if update else 'building'

    system_iu_progress(f'{action} dnxfirewall services')

    installed_services = [f for f in os.listdir('/etc/systemd/system/') if f.startswith('dnx-')]

    # ===========================================
    # INSTALL / UPDATING SERVICE FILES
    # ===========================================
    local_services = [f for f in os.listdir(f'{UTILITY_DIR}/services') if f not in ignore_list]
    for service in local_services:

        shell_run(f'cp {UTILITY_DIR}/services/{service} /etc/systemd/system/')

        if (service not in installed_services):
            shell_run(f'systemctl enable {service}')

    # required for systemd
    shell_run('systemctl daemon-reload')

    if (not update):
        shell_run(f'systemctl enable nginx')

    # ===========================================
    # REMOVE DEPRECATED SERVICE FILES
    # ===========================================
    deprecated_services = [f for f in installed_services if f not in local_services]
    for service in deprecated_services:

        # this isn't a big deal. it's possible to have already been done, so we can ignore any error.
        try:
            shell_run(f'systemctl disable {service}')
        except CalledProcessError:
            pass

        shell_run(f'rm /etc/systemd/system/{service}')

# ============================
# INITIAL IPTABLES SETUP
# ============================
def configure_iptables() -> None:
    system_iu_progress('loading default iptables')

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

def signature_update(force: bool = False, system_update: bool = False) -> bool:
    import dnx_control.system.signature_update as signature_updater

    ts_print('security signature updater initiated.')
    # ===========================================
    # INITIAL FILE CHECKSUM INFORMATION DOWNLOAD
    # ===========================================
    ts_print('downloading initial file integrity information from remote server.')
    file_validations: list[tuple] = []
    for attempt in range(1, 4):
        if file_validations := signature_updater.get_file_validations():
            break

        err_print(f'unable to download file validation information. tries: {attempt}/3')

    else:
        ts_print(f'retry limit reached.')
        hardout('try again later. exiting...')

    # ===========================================
    # REMOTE SIGNATURE VERSION INFORMATION
    # ===========================================
    ts_print('looking up remote signature version for compatibility.')
    remote_version = 99991231
    rsv_name, rsv_hash = file_validations[0]
    for attempt in range(1, 4):

        error, remote_version = signature_updater.get_remote_version(rsv_name)
        if (not error):

            if signature_updater.validate_file_download(f'{rsv_name}_TEMP', rsv_hash):
                break

        err_print(f'unable to validate signature versioning information. tries: {attempt}/3')

    else:
        ts_print(f'retry limit reached. check connection and try again later.')
        hardout('exiting...')

    # system update will ignore the signature version check and force the update.
    if not signature_updater.compare_signature_version(remote_version):
        hardout('a system update is required to support the latest signature sets.')

    # ===========================================
    # REMOTE SIGNATURE MANIFEST
    # ===========================================
    ts_print('downloading remote signature manifest.')
    remote_manifest: SIGNATURE_MANIFEST = []
    rsm_name, rsm_hash = file_validations[1]
    for attempt in range(1, 4):

        # downloading manifest of signature files to be downloaded.
        remote_manifest = signature_updater.get_remote_signature_manifest(rsm_name)
        if (remote_manifest):

            if signature_updater.validate_file_download(f'{rsm_name}_TEMP', rsm_hash):
                break

        err_print(f'unable to validate remote signature manifest. tries: {attempt}/3')

    else:
        ts_print(f'retry limit reached. check connection and try again later.')
        hardout('exiting...')

    # ===========================================
    # FILTERING UNCHANGED FILES - EARLY EXIT
    # ===========================================
    # note: a force removes the local manifest file which makes the file check think we need to download everything.
    if (force):
        os.remove(f'dnx_profile/signatures/{rsm_name}')

    update_msg = []
    # checking local manifest for files that have not changed and removing them from the list.
    # separate lists are for better reporting to the user.
    missing_files, changed_files = signature_updater.check_for_file_changes(rsm_name, remote_manifest)
    if (missing_files):
        update_msg.append(f'{len(missing_files)} new files')

    if (changed_files):
        update_msg.append(f'{len(changed_files)} changed files')

    update_msg = ' and '.join(update_msg)

    download_targets: SIGNATURE_MANIFEST = [*missing_files, *changed_files]
    if (download_targets):
        ts_print(f'identified {update_msg}. starting download...')

    else:
        ts_print('there are no signature updates available.')

        signature_updater.cleanup_temp_files()

        return False

    # ===========================================
    # DOWNLOADING NECESSARY FILES
    # ===========================================
    # TODO: make update in progress check happen before the download starts also to prevent temp files being overwritten
    #   in a partial state when another update process is trying to move them.
    #   - give option to continue or exit since it could be from a previous update that was interrupted.
    download_failure_list: SIGNATURE_MANIFEST = []
    checksum_failure_list: SIGNATURE_MANIFEST = []

    signature_update_progress = create_progress_bar(len(download_targets))

    for attempt in range(3):

        success = 0
        # retries only need to download the files that are remaining
        # converting to set to remove duplicates
        if (attempt > 0):
            signature_update_progress('incomplete', success)
            err_print(f'({len(checksum_failure_list)}) signature download errors detected. tries: {attempt}/3')

            # dedup with a set then converting back to a list
            download_targets = list({*download_failure_list, *checksum_failure_list})

            signature_update_progress = create_progress_bar(len(download_targets))

            # clearing trackers for the next attempt if needed.
            download_failure_list.clear()
            checksum_failure_list.clear()

        for target in download_targets:
            signature_update_progress(f'downloading {target.name}', progress_override=success)

            # downloading signatures and running checksum validation.
            if not signature_updater.download_signature_file(target):
                download_failure_list.append(target)
                # if (args.verbose_set):
                #     ts_print(f'download failed for {file}')

            else:
                check_passed = signature_updater.validate_signature_file(target)
                if (not check_passed):
                    checksum_failure_list.append(target)

                else:
                    success += 1
                    # if (args.verbose_set):
                    #     ts_print(f'checksum failed for {file}')

        if (not download_failure_list and not checksum_failure_list):
            signature_update_progress('done. installing...', progress_override=success, final=True)
            break

    # will give the user the option to load the signatures that downloaded successfully or exit.
    # TODO: i do not see where the option is actually given for this. it looks like it will just continue on its own.
    #   either current me is dumb or past me was dumb. i'm not sure which.
    else:
        ts_print(f'retry limit reached.')
        ts_print(f'{len(download_failure_list)} signatures failed to download.')
        ts_print(f'{len(checksum_failure_list)} signatures failed checksum validation.')

    # ===========================================
    # COPYING DOWNLOADED FILES TO SIGNATURE DIR
    # ===========================================
    # settings the flag to identify a file move in progress or partial signature update.
    if not signature_updater.set_signature_update_flag():
        err_print('signature update may already be in in progress or a previous update was interrupted.')

        signature_updater.set_signature_update_flag(override=True)

    signature_updater.move_signature_files(download_targets, checksum_failure_list)

    ts_print('signatures installed. setting permissions.')

    # probably not needed, but doing anyway for consistency.
    set_signature_permissions()

    # ===========================================
    # UPDATE LOCAL CONFIGURATION FILES
    # ===========================================
    # setting geolocation data in ip proxy/profile_0 to the newly downloaded set.
    # todo: make this check for a file change before updating the config file so we dont needlessly touch config files.
    geolocation_cfg = load_data('geolocation.cfg', filepath='dnx_profile/signatures/configuration')
    ipp_default_profile = load_data('profiles/profile_0.cfg', cfg_type='system/security/ip')

    ipp_default_profile['geolocation'] = geolocation_cfg['geolocation']

    # :bug: this is not terrible, but overwrites a file tracked by git, and can make some operations more difficult.
    # writing to temp file, changing the owner and permissions, then renaming over the original file.
    write_data(ipp_default_profile, 'profile_0.temp', cfg_type='system/security/ip/profiles')

    geo_cfg_path_temp = 'dnx_profile/data/system/security/ip/profiles/profile_0.temp'
    geo_cfg_path = 'dnx_profile/data/system/security/ip/profiles/profile_0.cfg'

    change_file_owner(geo_cfg_path_temp)
    os.rename(geo_cfg_path_temp, geo_cfg_path)

    # ===========================================
    # CLEANUP
    # ===========================================
    signature_updater.clear_signature_update_flag()

    final_msg = 'signature update complete.'

    if (not system_update):
        final_msg += ' restart security modules to apply the changes.'

    ts_print(final_msg)

    return True

# TODO: add a general check for system updates for changes and skip certain steps if possible.
#  - for example, skip recompiling cython or c modules if they have not changed.
#    cython does this automatically, but the updater will still run the compile steps and show the progress bar as if
#    it is doing something.
def run():
    global NUMBER_OF_IU_TASKS
    global system_iu_progress

    # to simplify folder/file naming
    os.chdir(HOME_DIR)

    # signature updates are handled separately from the rest of the build process unless the system is being updated.
    if (args._update_signatures):
        signature_update(args.force)

        return

    NUMBER_OF_IU_TASKS += 1  # copying service files
    if (not args._update_system):
        set_branch()
        configure_interfaces()

    if (not args._update_system) and (args._update_system and args.iptables):
        NUMBER_OF_IU_TASKS += 1  # building iptables

    # will hold all dynamically set commands prior to execution to get an accurate count for progress bar.
    dynamic_commands: list[tuple[str, Optional[str]]] = []

    if ('BRANCH_OVERRIDE' in os.environ):
        branch = os.environ['BRANCH_OVERRIDE']
    else:
        branch = checkout_configured_branch()

    # TODO: add a check to see if the branch is up to date and skip to signature update if it is.
    if (args._update_system):
        dynamic_commands.extend(update_local_branch(branch))

    # packages will be installed during initial installation automatically.
    # if update is set, the default is to not update packages.
    if (not args._update_system) or (args._update_system and args.packages):
        dynamic_commands.extend(install_packages())

    if (not args._update_system):
        dynamic_commands.extend(configure_webui())

    compile_extensions(count_only=True)

    NUMBER_OF_IU_TASKS += len([1 for k, v in dynamic_commands if v])

    action = 'update' if args._update_system else 'deployment'
    ts_print(f'starting dnxfirewall {action}...')
    line_print()

    # NOTE: ensuring the progress bar count is properly reflected.
    if (not args._update_system):
        build_libraries(count_only=True)

    system_iu_progress = create_progress_bar(NUMBER_OF_IU_TASKS)

    system_iu_progress('')  # this will render 0% bar, so we don't need to use offsets.
    for command, desc in dynamic_commands:

        if (desc):
            system_iu_progress(desc)

        shell_run(command)

    # building netfilter libs from source.
    # keeping this separate from packages since we cannot guarantee the user distro's versioning meets the minimum
    # requirements [source is locally contained within dnxfirewall repo].
    if (not args._update_system):
        build_libraries()

    # this must be done after the netfilter libs are built.
    for command, desc in compile_extensions():

        if (desc):
            system_iu_progress(desc)

        shell_run(command)

    if (not args._update_system) or (args._update_system and args.iptables):
        configure_iptables()

    set_permissions()

    set_services(args._update_system)
    if (not args._update_system):
        mark_completion_flag()

    system_iu_progress(f'dnxfirewall {action} complete...', final=True)

    # signatures will be updated during initial installation or system update automatically.
    signatures_updated = signature_update(system_update=True)

    if (not args._update_system):
        ts_print('control of the WAN interface configuration has been taken by dnxfirewall.')
        ts_print('use the webui to configure a static ip or enable ssh access if needed.')
        ts_print('restart the system then navigate to https://192.168.83.1 from LAN to manage.')

    else:
        ts_print('dnxfirewall services restart required. a full system restart is recommended.')

    hardout()


if INITIALIZE_MODULE('autoloader'):
    LOG_NAME: str = 'system'
    SYSTEM_DIR: str = 'dnx_profile'
    UTILITY_DIR: str = 'dnx_profile/utils'

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

    # checks that do not apply to signature update command.
    if (not args._update_signatures):
        # this uses the config manager, so must be called after log initialization
        check_already_ran()

    NUMBER_OF_IU_TASKS = 0
    system_iu_progress = create_progress_bar(NUMBER_OF_IU_TASKS)  # dummy bar