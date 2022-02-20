#!/usr/bin/env python3

from __future__ import annotations

from typing import Optional, Union

import os
import sys
import time
import importlib

from functools import partial
from subprocess import check_call, DEVNULL, CalledProcessError

hardout = partial(os._exit, 0)

dnx_run = partial(check_call, stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL)

# =========================
# MOD NAME -> MOD LOCATION
# =========================
MODULE_MAPPING: dict[str, dict[str, Union[str, bool, list]]] = {
    # HELPERS
    'all': {'module': '', 'exclude': ['status', 'cli'], 'priv': True},

    # INFORMATIONAL
    'modstat': {'module': '', 'exclude': ['start', 'stop', 'restart', 'status', 'cli'], 'priv': True},

    # WEBUI
    'webui': {'module': '', 'exclude': ['cli'], 'priv': False},

    # SECURITY MODULES
    'cfirewall': {'module': 'dnx_secmods.cfirewall.fw_init', 'exclude': [], 'priv': True},
    'dns_proxy': {'module': 'dnx_secmods.dns_proxy.dns_proxy', 'exclude': [], 'priv': True},
    'ip_proxy': {'module': 'dnx_secmods.ip_proxy.ip_proxy', 'exclude': [], 'priv': True},
    'ips_ids': {'module': 'dnx_secmods.ips_ids.ips_ids', 'exclude': [], 'priv': True},

    # NETWORK MODULES
    'dhcp_server': {'module': 'dnx_netmods.dhcp_server.dhcp_server', 'exclude': [], 'priv': True},

    # ROUTINES
    'database': {'module': 'dnx_routines.database.ddb_main', 'exclude': [], 'priv': False},
    'logging': {'module': 'dnx_routines.logging.log_main', 'exclude': [], 'priv': False},

    'iptables': {'module': 'dnx_routines.configure.iptables', 'exclude': [], 'priv': True},

    # SYSTEM
    'startup': {'module': 'dnx_system.startup_proc', 'exclude': [], 'priv': True},
    'interface': {'module': 'dnx_system.interface_services', 'exclude': [], 'priv': False},
    'syscontrol': {'module': 'dnx_system.sys_control', 'exclude': [], 'priv': True}
}

systemctl_ret_codes: dict[int,str] = {
    0: 'program is running or service is OK',
    1: 'program dead and /var/run pid file exists',
    2: 'program dead and /var/lock lock file exists',
    3: 'program not running',
    4: 'program service status is unknown',
}

def parse_args():
    module: str = get_index(1, cname='module')
    command: str = get_index(2, cname='command')

    # checking if the specified module exists then checking if subsequent command is valid for the module
    mod_settings = check_module(module)
    if (command in mod_settings['exclude']):
        exit(f'\n{command.upper()} not valid for {module.upper()}')

    check_priv(module, command, mod_settings)

    os.environ['PASSTHROUGH_ARGS'] = ','.join(sys.argv[3:])

    return module, command, mod_settings['module']

def get_index(idx: int, /, *, cname='') -> str:
    try:
        return sys.argv[idx]
    except IndexError:
        exit(f'\nUNKNOWN {cname.upper()} -> see --help\n')

def check_module(mod: str, /) -> dict:
    valid_module = MODULE_MAPPING.get(mod, None)
    if (valid_module is None):
        exit(f'\nUNKNOWN MODULE -> see --help\n')

    return valid_module

def check_priv(mod: str, cmd: str, modset: dict) -> None:
    if (os.getuid() and modset['priv'] and cmd == 'cli'):
        exit(f'\nDNXFIREWALL {mod.upper()} requires root to run in CLI.\n')

def utility_commands(mod: str, cmd: Optional[str] = None) -> None:
    if (mod == 'modstat'):

        svc_len: int = 0
        down_detected: bool = False

        status: list[Optional[list[str, str]]] = []
        for _mod in list(MODULE_MAPPING)[1:]:
            service = f'dnx-{_mod.replace("_", "-")}'

            svc_len = len(service) if len(service) > svc_len else svc_len

            try:
                dnx_run(f'sudo systemctl status {service}', shell=True)
            except CalledProcessError as E:
                status.append([service, f'down  code={E.returncode}  msg="{systemctl_ret_codes.get(E.returncode, "")}"'])

                down_detected = True

            else:
                status.append([service, 'up'])

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

    elif mod == 'all':
        for svc in list(MODULE_MAPPING)[2:]:
            service = f'dnx-{mod.replace("_", "-")}'

            try:
                dnx_run(['systemctl', service, cmd])
            except CalledProcessError:
                print(f'{svc.ljust(11)} => {"fail".rjust(7)}')
            else:
                print(f'{svc.ljust(11)} => {"success".rjust(7)}')

def service_commands(mod: str, cmd: str) -> None:
    try:
        dnx_run(['systemctl', mod, cmd])
    except CalledProcessError:
        print(f'{mod} service {cmd} failed. check journal.')

    else:
        print(f'{mod} service {cmd} successful.')

def run_cli(mod: str, mod_loc: str) -> None:
    os.environ['INIT_MODULE'] = 'YES'

    try:
        importlib.import_module(mod_loc)
    except Exception as E:
        print(f'{mod} cli run failure. => {E}')
        hardout()


if (__name__ == '__main__'):
    mod_name, mod_cmd, mod_path = parse_args()

    if (not mod_path):
        utility_commands(mod_name)

    elif mod_cmd in ['', 'cli']:
        run_cli(mod_name, mod_path)

    else:
        service_commands(mod_name, mod_cmd)
