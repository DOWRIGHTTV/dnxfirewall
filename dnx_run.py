#!/usr/bin/env python3

from __future__ import annotations

from typing import Optional, Union

import os
import sys
import time
import importlib

from functools import partial
from subprocess import check_call, DEVNULL, CalledProcessError

HOME_DIR = os.environ.get('HOME_DIR', '/home/dnx/dnxfirewall')

hardout = partial(os._exit, 0)
dnx_run = partial(check_call, stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL)

# =========================
# MOD NAME -> MOD LOCATION
# =========================
MODULE_MAPPING: dict[str, dict[str, Union[str, bool, list]]] = {
    # HELPERS
    'all': {'module': '', 'exclude': ['status', 'cli'], 'priv': True, 'service': False},

    # WEBUI
    'webui': {'module': '', 'exclude': ['cli'], 'priv': False, 'service': True},

    # SECURITY MODULES
    'cfirewall': {'module': 'dnx_secmods.cfirewall.fw_init', 'exclude': [], 'priv': True, 'service': True},
    'dns_proxy': {'module': 'dnx_secmods.dns_proxy.dns_proxy', 'exclude': [], 'priv': True, 'service': True},
    'ip_proxy': {'module': 'dnx_secmods.ip_proxy.ip_proxy', 'exclude': [], 'priv': True, 'service': True},
    'ips_ids': {'module': 'dnx_secmods.ips_ids.ips_ids', 'exclude': [], 'priv': True, 'service': True},

    # NETWORK MODULES
    'dhcp_server': {'module': 'dnx_netmods.dhcp_server.dhcp_server', 'exclude': [], 'priv': True, 'service': True},

    # ROUTINES
    'database': {'module': 'dnx_routines.database.ddb_main', 'exclude': [], 'priv': False, 'service': True},
    'logging': {'module': 'dnx_routines.logging.log_main', 'exclude': [], 'priv': False, 'service': True},

    'iptables': {'module': 'dnx_routines.configure.iptables', 'exclude': [], 'priv': True, 'service': False},

    # SYSTEM
    'startup': {'module': 'dnx_system.startup_proc', 'exclude': [], 'priv': True, 'service': True},
    'interface': {'module': 'dnx_system.interface_services', 'exclude': [], 'priv': False, 'service': True},
    'syscontrol': {'module': 'dnx_system.sys_control', 'exclude': [], 'priv': True, 'service': True}
}
SERVICE_MODULES = [f'dnx-{mod.replace("_", "-")}' for mod, modset in MODULE_MAPPING.items() if modset['service']]

COMMANDS = {
    'start': {'priv': True},
    'restart': {'priv': True},
    'stop': {'priv': True},
    'modstat': {'priv': True}
}

systemctl_ret_codes: dict[int, str] = {
    0: 'program is running or service is OK',
    1: 'program dead and /var/run pid file exists',
    2: 'program dead and /var/lock lock file exists',
    3: 'program not running',
    4: 'program service status is unknown',
}

def parse_args() -> tuple[str, str, dict]:
    command: str = get_index(1, cname='command')
    module: str = get_index(2, cname='module')

    # checking if the specified module exists, then checking if subsequent command is valid for the module
    mod_settings = check_module(module)
    if (command in mod_settings['exclude']):
        exit(f'\n{command.upper()} not valid for {module.upper()}')

    check_command(command, module, mod_settings)

    os.environ['PASSTHROUGH_ARGS'] = ','.join(sys.argv[3:])

    return module, command, mod_settings

def get_index(idx: int, /, *, cname='') -> str:
    try:
        return sys.argv[idx]
    except IndexError:
        exit(f'\nUNKNOWN {cname.upper()} -> see --help\n')

def check_module(mod: str, /) -> dict:
    valid_module = MODULE_MAPPING.get(mod)
    if (not valid_module):
        exit('\nUNKNOWN MODULE -> see --help\n')

    return valid_module

def check_command(cmd: str, mod: str, modset: dict) -> None:
    if (cmd not in COMMANDS):
        exit(f'\nUNKNOWN COMMAND ({cmd.upper()}) -> see --help\n')

    if (cmd == 'cli' and not modset['priv']):
        return

    root = not os.getuid()
    if (not root and modset['priv']):
        exit(f'\nDNXFIREWALL command {cmd.upper()} requires root for module {mod.upper()}\n')

def utility_commands(mod: str, cmd: str = '') -> None:
    if (mod == 'modstat'):

        svc_len: int = 0
        down_detected: bool = False

        status: list[Optional[list[str, str]]] = []
        for svc in SERVICE_MODULES:
            svc_len = len(svc) if len(svc) > svc_len else svc_len

            try:
                dnx_run(f'sudo systemctl status {svc}', shell=True)
            except CalledProcessError as E:
                status.append([svc, f'down  code={E.returncode}  msg="{systemctl_ret_codes.get(E.returncode, "")}"'])

                down_detected = True

            else:
                status.append([svc, 'up'])

        # =================================
        # OUTPUT - Justified left<==>right
        # =================================
        # dnx-cfirewall   => down (code=4)
        print('# =====================')
        print('# DNXFIREWALL SERVICES')
        print('# =====================')
        for svc, result in status:
            time.sleep(0.05)
            print(f'{svc.ljust(svc_len)} => {result.rjust(4)}')

        if (down_detected):
            print(f'\ndowned service detected. check journal for more details.')

    elif (mod == 'all'):
        for svc in SERVICE_MODULES:
            try:
                dnx_run(f'sudo systemctl {cmd} {svc}', shell=True)
            except CalledProcessError:
                print(f'{svc.ljust(11)} => {"fail".rjust(7)}')
            else:
                print(f'{svc.ljust(11)} => {"success".rjust(7)}')

def service_commands(mod: str, cmd: str) -> None:
    svc = f'dnx-{mod.replace("_", "-")}'
    try:
        dnx_run(f'sudo systemctl {cmd} {svc}', shell=True)
    except CalledProcessError as cpe:
        print(f'{svc} service {cmd} failed. check journal. => msg={cpe}')

    else:
        print(f'{svc} service {cmd} successful.')

def run_cli(mod: str, mod_loc: str) -> None:
    os.environ['INIT_MODULE'] = 'YES'

    mod_path = '/'.join([HOME_DIR, *mod_loc.split('.')[:2]])

    # inserting the module path into the system path so intra-module imports can be done locally
    sys.path.insert(0, mod_path)

    try:
        importlib.import_module(mod_loc)
    except Exception as E:
        print(f'{mod} cli run failure. => {E}')
        hardout()


if (__name__ == '__main__'):
    mod_name, mod_cmd, mod_set = parse_args()

    if mod_set['service']:
        service_commands(mod_name, mod_cmd)

    if (not mod_set['module']):
        utility_commands(mod_name, mod_cmd)

    elif mod_cmd in ['modstat', 'cli']:
        run_cli(mod_name, mod_set['module'])
