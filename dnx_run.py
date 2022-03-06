#!/usr/bin/env python3

from __future__ import annotations

from typing import Optional, Union

import os
import sys
import time
import importlib
import traceback

from functools import partial
from subprocess import run, DEVNULL, CalledProcessError

HOME_DIR = os.environ.get('HOME_DIR', '/home/dnx/dnxfirewall')

hardout = partial(os._exit, 0)
dnx_run = partial(run, check=True, stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL)

# =========================
# MOD NAME -> MOD LOCATION
# =========================
MODULE_MAPPING: dict[str, dict[str, Union[str, bool, list]]] = {
    # HELPERS
    'all': {'module': '', 'exclude': ['status', 'cli'], 'priv': True, 'service': False},

    # WEBUI
    'webui': {'module': '', 'exclude': ['cli'], 'priv': False, 'service': True, 'environ': ['webui', '1']},

    # SECURITY MODULES
    'cfirewall': {'module': 'dnx_secmods.cfirewall', 'exclude': [], 'priv': True, 'service': True},
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
    'start': {'priv': True, 'module': True},
    'restart': {'priv': True, 'module': True},
    'stop': {'priv': True, 'module': True},
    'status': {'priv': True, 'module': True},
    'cli': {'priv': True, 'module': True},
    'modstat': {'priv': True, 'module': False}
}

systemctl_ret_codes: dict[int, str] = {
    0: 'program is running or service is OK',
    1: 'program dead and /var/run pid file exists',
    2: 'program dead and /var/lock lock file exists',
    3: 'program not running',
    4: 'program service status is unknown',
}

def sprint(msg: str, /) -> None:
    print(f'\n{msg}\n')

# ;)
def sexit(msg: str, /) -> None:
    exit(f'\n{msg}\n')

def parse_args() -> tuple[str, str, dict]:
    command: str = get_index(1, cname='command')
    module: str = get_index(2, cname='module')

    mod_settings = check_module(module)
    check_command(command, module, mod_settings)

    os.environ['PASSTHROUGH_ARGS'] = ','.join(sys.argv[3:])

    return module, command, mod_settings

def get_index(idx: int, /, *, cname: str = '') -> Union[str, object]:
    try:
        return sys.argv[idx]
    except IndexError:
        return object()  # sentinel

def check_module(mod: str, /) -> dict:
    return MODULE_MAPPING.get(mod, {})

def check_command(cmd: str, mod: str, modset: dict) -> None:
    cmd_info = COMMANDS.get(cmd, None)
    if (not cmd_info):
        sexit(f'UNKNOWN COMMAND ({cmd.upper()}) -> see --help')

    root = not os.getuid()

    # command level privilege
    if (not root and cmd_info['priv']):
        sexit(f'DNXFIREWALL command {cmd.upper()} requires root')

    # the command does not require a module
    if (not cmd_info['module']):
        return

    # ================
    # MODULE REQUIRED
    # ================
    if (not modset):
        sexit('UNKNOWN MODULE -> see --help')

    # checking if command is valid for the module
    if (cmd in modset['exclude']):
        sexit(f'{cmd.upper()} not valid for {mod.upper()}')

    # module level privilege
    if (not root and modset['priv']):
        sexit(f'DNXFIREWALL command {cmd.upper()} requires root for module {mod.upper()}')

def modstat_command() -> None:

    svc_len: int = 0
    down_detected: bool = False

    status: list[Optional[list[str, str]]] = []
    for svc in SERVICE_MODULES:
        svc_len = len(svc) if len(svc) > svc_len else svc_len

        try:
            dnx_run(f'sudo systemctl status {svc}', shell=True)
        except CalledProcessError as cpe:
            status.append(
                [svc, f'down  code={cpe.returncode}  msg="{systemctl_ret_codes.get(cpe.returncode, "")}"']
            )

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

def service_command(mod: str, cmd: str) -> None:
    if (mod == 'all'):
        for svc in SERVICE_MODULES:
            try:
                dnx_run(f'sudo systemctl {cmd} {svc}', shell=True)
            except CalledProcessError:
                sprint(f'{svc.ljust(15)} => {"fail".rjust(7)}')
            else:
                sprint(f'{svc.ljust(15)} => {"success".rjust(7)}')

        return

    svc = f'dnx-{mod.replace("_", "-")}'
    try:
        dnx_run(f'sudo systemctl {cmd} {svc}', shell=True)
    except CalledProcessError as cpe:
        if (cmd == 'status'):
            sprint(
                f'{svc.ljust(15)} => down  code={cpe.returncode} msg="{systemctl_ret_codes.get(cpe.returncode, "")}"'
            )
        else:
            sprint(f'{svc} service {cmd} failed. check journal. => msg={cpe}')

    else:
        if (cmd == 'status'):
            sprint(f'{svc.ljust(15)} => {"up".rjust(4)}')

        else:
            sprint(f'{svc} service {cmd} successful.')

# using environ var to notify imported module to initialize and run. this was done because a normal function was causing
# issues with the linter thinking a ton of stuff was not defined. this could probably be done better.
# TODO: see if can be done better
def run_cli(mod: str, mod_loc: str) -> None:
    os.environ['INIT_MODULE'] = mod
    os.environ['HOME_DIR'] = HOME_DIR

    env = MODULE_MAPPING[mod].get('environ')
    if (env):
        os.environ[env[0]] = env[1]

    mod_path = '/'.join([HOME_DIR, *mod_loc.split('.')[:2]])

    sys.path.insert(0, HOME_DIR)
    # inserting the module path into the system path so intra-module imports can be done locally
    sys.path.insert(0, mod_path)

    try:
        dnx_mod = importlib.import_module(mod_loc)
    except Exception as E:
        sprint(f'{mod} (cli) import failure. => {E}')
        traceback.print_exc()

    else:
        try:
            dnx_mod.run()
        except Exception as E:
            sprint(f'{mod} (cli) run failure. => {E}')
            traceback.print_exc()

        except KeyboardInterrupt:
            sprint(f'{mod} (cli) interrupted')

    # this will make sure there are no dangling processes or threads on exit.
    hardout()


if (__name__ == '__main__'):
    mod_name, command, mod_set = parse_args()

    if (command == 'cli'):
        run_cli(mod_name, mod_set['module'])

    elif (command == 'modstat'):
        modstat_command()

    elif mod_set['service']:
        service_command(mod_name, command)

    else:
        print(f'<dnx> missing command logic for => mod={mod_name} command={command}')
