#!/usr/bin/env python3

from __future__ import annotations

from typing import Optional, Union, Iterable

import os
import sys
import time
import json
import importlib
import traceback

from functools import partial
from subprocess import run, DEVNULL, CalledProcessError

from dnx_cli.utils.shell_colors import text, styles

# HOME_DIR = os.environ.get('HOME_DIR', '/home/dnx/dnxfirewall')

# style aliases
BOLD = styles.bold

hardout = partial(os._exit, 0)
dnx_run = partial(run, check=True, stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL)
dnx_run_v = partial(run, check=True, stdin=DEVNULL)
def exclude(s: str, l: Iterable, /) -> list[str]:
    '''return a new list with specified string removed from the passed in list, set, tuple, dict.
    '''
    nl = list(l)
    nl.remove(s)

    return nl


COMMANDS: dict[str, dict[str, bool]] = {
    'help': {'description': 'Displays this menu', 'priv': False, 'module': False},
    'start': {'priv': True, 'module': True},
    'restart': {'priv': True, 'module': True},
    'stop': {'priv': True, 'module': True},
    'status': {'priv': True, 'module': True},
    'cli': {'priv': False, 'module': True},
    'modstat': {'priv': True, 'module': False},
    'compile': {'priv': True, 'module': False}
}

# =========================
# MOD NAME -> MOD LOCATION
# =========================
MODULE_MAPPING: dict[str, dict[str, Union[str, bool, list]]] = {
    # HELPERS
    'all': {'module': '', 'exclude': ['status', 'cli'], 'priv': True, 'service': False},

    # AUTOLOADER
    'autoloader': {
        'module': 'dnx_control.system.autoloader', 'exclude': exclude('cli', COMMANDS), 'priv': True, 'service': False
    },

    # DB TABLES
    'db-tables': {'module': 'dnx_routines.database', 'exclude': exclude('cli', COMMANDS), 'priv': False, 'service': False},

    # WEBUI
    'webui': {'module': '', 'exclude': ['cli'], 'priv': False, 'service': True, 'environ': ['webui', '1']},

    # SECURITY MODULES
    'cfirewall': {'module': 'dnx_secmods.cfirewall', 'exclude': [], 'priv': True, 'service': True},
    'dns-proxy': {'module': 'dnx_secmods.dns_proxy', 'exclude': ['compile'], 'priv': True, 'service': True},
    'ip-proxy': {'module': 'dnx_secmods.ip_proxy', 'exclude': ['compile'], 'priv': True, 'service': True},
    'ips-ids': {'module': 'dnx_secmods.ips_ids', 'exclude': ['compile'], 'priv': True, 'service': True},

    # NETWORK MODULES
    'dhcp-server': {
        'module': 'dnx_netmods.dhcp_server', 'exclude': ['compile'], 'priv': True, 'service': True
    },

    # ROUTINES
    'database': {'module': 'dnx_routines.database', 'exclude': ['compile'], 'priv': False, 'service': True},
    'logging': {'module': 'dnx_routines.logging.log_main', 'exclude': ['compile'], 'priv': False, 'service': True},

    'iptables': {
        'module': 'dnx_iptools.iptables', 'exclude': exclude('cli', COMMANDS), 'priv': True, 'service': False
    },

    # SYSTEM
    'startup': {'module': 'dnx_profile.startup_proc', 'exclude': ['compile'], 'priv': True, 'service': True},
    'interface': {'module': 'dnx_profile.interface_services', 'exclude': ['compile'], 'priv': False, 'service': True},
    'syscontrol': {'module': 'dnx_profile', 'exclude': ['compile'], 'priv': True, 'service': True},

    # COMPILE ONLY
    'dnx-nfqueue': {'module': '1', 'exclude': exclude('compile', COMMANDS), 'priv': True, 'service': False},
    'cprotocol-tools': {'module': '1', 'exclude': exclude('compile', COMMANDS), 'priv': True, 'service': False},
    'hash-trie': {'module': '1', 'exclude': exclude('compile', COMMANDS), 'priv': True, 'service': False},

    # TESTS
    'trie-test': {
        'module': 'dnx_profile.utils.unit_tests.trie_test', 'exclude': exclude('cli', COMMANDS), 'priv': False, 'service': False
    }
}
SERVICE_MODULES = [f'dnx-{mod}' for mod, modset in MODULE_MAPPING.items() if modset['service']]

systemctl_ret_codes: dict[int, str] = {
    0: text.lightgrey('program ') + text.yellow('is running or service is ', style=None) + text.green('OK'),
    1: text.lightgrey('program ') + text.yellow('dead and /var/run pid file exists', style=None),
    2: text.lightgrey('program ') + text.yellow('dead and /var/lock lock file exists', style=None),
    3: text.lightgrey('program ') + text.red('not running'),
    4: text.lightgrey('program ') + text.yellow('service status is ', style=None) + text.darkgrey('UNKNOWN'),
}

def sprint(msg: str, /) -> None:
    print(f'\n{msg}\n')

# ;)
def sexit(msg: str, /) -> None:
    exit(f'\n{msg}\n')

def parse_args() -> tuple[str, str, dict]:
    cmd: str = get_index(1)
    module: str = get_index(2)

    mod_settings = check_module(module)
    check_command(cmd, module, mod_settings)

    os.environ['PASSTHROUGH_ARGS'] = ','.join(sys.argv[3:])

    return module, cmd, mod_settings

def get_index(idx: int, /) -> str:
    try:
        return sys.argv[idx]
    except IndexError:
        return 'X'

def check_module(mod: str, /) -> dict:
    return MODULE_MAPPING.get(mod, {})

def check_command(cmd: str, mod: str, modset: dict) -> None:
    cmd_info = COMMANDS.get(cmd, None)
    if (not cmd_info):
        sexit(
            text.red('Error! ') +
            text.lightgrey('Unknown Command. ⟶ See help for existing commands')
        )

    root = not os.getuid()

    # command level privilege
    if (not root and cmd_info['priv']):
        sexit(
            text.lightgrey(f'DNXFIREWALL command "{cmd.upper()}" requires ') +
            text.red('root') +
            text.lightgrey(' privileges.')
        )

    # the command does not require a module
    if (not cmd_info['module']):
        return

    # ================
    # MODULE REQUIRED
    # ================
    if (not modset):
        sexit(
            text.red('Error! ') +
            text.lightgrey('Unknown Module. Module does not exist. ⟶ See help')
        )

    # checking if command is valid for the module
    if (cmd in modset['exclude']):
        sexit(
            text.lightgrey(f' "{cmd.upper()}" ') +
            text.red(f'not valid') +
            text.lightgrey(f' for  "{mod.upper()}".')
        )

    # module level privilege
    if (not root and modset['priv']):
        sexit(
            text.lightgrey(f'DNXFIREWALL command "{cmd.upper()}" requires ') +
            text.red('root') +
            text.lightgrey(' privileges.')
        )

def help_command() -> None:
    print('\n', text.blue('----------- ') + text.lightgrey(' | Commands | ') + text.blue('-----------'))

    convert_bool = {True: text.red('yes'), False: text.green('no')}
    # iterate over COMMANDS dict and print each to a line, adding : inbetween
    # I want to replace priv with privilege for readability, will experiment.
    # TODO: better way to do this?
    for cmd, opts in COMMANDS.items():
        description = opts.get('description', '')
        cmd_opts = {
            'description': text.yellow(description, style=None),
            'priv_required': convert_bool[opts['priv']],
            'has_module': convert_bool[opts['module']]
        }
        if (not description):
            cmd_opts.pop('description')

        print(text.lightgrey(f'{cmd}: '))
        for opt, val in cmd_opts.items():
            print('    ', f'{opt.ljust(14)}... {val}')

    print('\n', text.blue('----------- ') + text.lightgrey(' | Ret Codes | ') + text.blue('-----------'))

    for code, msg in systemctl_ret_codes.items():
        print(text.lightgrey(f'code: {code}'.ljust(10)), msg)

def modstat_command() -> None:

    svc_len: int = 0
    down_detected: bool = False

    status: list[list[str, str]] = []
    for svc in SERVICE_MODULES:
        svc_len = len(svc) if len(svc) > svc_len else svc_len

        try:
            dnx_run(f'sudo systemctl status {svc}', shell=True)
        except CalledProcessError as cpe:
            status.append([svc,
                text.red('down ') + text.darkgrey('code=') + text.lightgrey(f'{cpe.returncode} ') +
                text.darkgrey(f'msg="{systemctl_ret_codes.get(cpe.returncode, "")}"')
            ])

            down_detected = True

        else:
            status.append([svc, text.green('up')])

    # =================================
    # OUTPUT - Justified left<==>right
    # =================================
    # dnx-cfirewall   => down (code=4)
    print(text.blue('░█▀▄░█▀█░█░█  ░█▀▀░█▀▀░█▀▄░█░█░▀█▀░█▀▀░█▀▀░█▀▀'))
    print(text.blue('░█░█░█░█░▄▀▄  ░▀▀█░█▀▀░█▀▄░▀▄▀░░█░░█░░░█▀▀░▀▀█'))
    print(text.blue('░▀▀░░▀░▀░▀░▀  ░▀▀▀░▀▀▀░▀░▀░░▀░░▀▀▀░▀▀▀░▀▀▀░▀▀▀'))
    for svc, result in status:
        time.sleep(0.05)
        print(text.darkgrey(f'{svc.ljust(svc_len)} ⟶ {result.rjust(4)}'))

    if (down_detected):
        print(
            text.red(f'\nALERT! ') + text.lightgrey(f'Down service(s) detected! ')
        )
        print(text.lightgrey('Check journal for more details.'))

    else:
        print(text.green(f'\nAll services running!'))

def service_command(mod: str, cmd: str) -> None:
    if (mod == 'all'):
        for svc in SERVICE_MODULES:
            try:
                if (mod == 'webui'):
                    dnx_run(f'sudo systemctl {cmd} nginx', shell=True)

                dnx_run(f'sudo systemctl {cmd} {svc}', shell=True)
            except CalledProcessError:
                sprint(text.red(f'{svc.ljust(15)} ⟶ {"fail".rjust(7)}'))
            else:
                sprint(text.green(f'{svc.ljust(15)} ⟶ {"success".rjust(7)}'))

        return

    svc = f'dnx-{mod.replace("_", "-")}'
    try:
        if (mod == 'webui'):
            dnx_run(f'sudo systemctl {cmd} nginx', shell=True)

        dnx_run(f'sudo systemctl {cmd} {svc}', shell=True)
    except CalledProcessError as cpe:
        if (cmd == 'status'):
            sprint(
                text.lightgrey(f'{svc.ljust(15)} ⟶ ') + text.red(f'down ') + text.lightgrey(f'code="{cpe.returncode}') +
                text.lightgrey(f'msg="{systemctl_ret_codes.get(cpe.returncode, "")}"')
                )
        else:
            sprint(
                text.lightgrey(f'"{svc}" service "{cmd}"') + text.red(f'failed.') +
                text.darkgrey(f'Check the journal for more details. ⟶ msg="{cpe}"')
            )

    else:
        if (cmd == 'status'):
            sprint(text.lightgrey(f'{svc.ljust(15)} ⟶ ') + text.green(f'{"up".rjust(4)}'))
        else:
            sprint(text.lightgrey(f'svc ') + text.lightgrey(f'service "{cmd}"') + text.green(' successful.'))

# using environ var to notify imported module to initialize and run.
# this was done because a normal function was causing issues with the linter thinking a ton of stuff was not defined.
# this could probably be done better.
# TODO: see if can be done better
def run_cli(mod: str, mod_loc: str) -> None:
    os.environ['INIT_MODULE'] = mod

    from dnx_gentools.def_constants import HOME_DIR

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
        except KeyboardInterrupt:
            sprint(text.lightgrey(f'{mod} ') + text.red('(cli) interrupted!'))
        except Exception as E:
            sprint(text.lightgrey(f'{mod} ') + text.red(f'(cli) run failure. ⟶ {E}'))
            traceback.print_exc()

    # this will make sure there are no dangling processes or threads on exit.
    hardout()


if (__name__ == '__main__'):
    mod_name, command, mod_set = parse_args()

    if (command == 'help'):
        help_command()

    elif (command == 'cli'):
        run_cli(mod_name, mod_set['module'])

    elif (command == 'modstat'):
        modstat_command()

    elif(command == 'compile'):
        from dnx_gentools.def_constants import HOME_DIR

        file_path = f'{HOME_DIR}/dnx_profile/utils/compiler/{mod_name.replace("-", "_")}.py'
        try:
            dnx_run_v(f'sudo HOME_DIR={HOME_DIR} python3 {file_path} build_ext --inplace', shell=True)
        except CalledProcessError as cpe:
            sprint(text.lightgrey(f'{mod_name} compile has') + text.red(' failed ') + text.lightgrey(f'⟶ {cpe}!'))

        else:
            sprint(text.lightgrey(f'{mod_name} compile has') + text.green(' succeeded') + text.lightgrey('!'))

    elif (mod_name == 'all' or mod_set['service']):
        service_command(mod_name, command)

    else:
        sprint(text.lightgrey(f'<dnx> ') + text.red(f'missing command logic for ⟶ mod={mod_name} command={command}'))
