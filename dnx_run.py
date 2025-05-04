#!/usr/bin/env python3

from __future__ import annotations

# from typing import Union, Iterable

import os
import sys
# import time
import importlib

from functools import partial
from subprocess import run, CalledProcessError

from dnx_gentools.def_exceptions import ModuleReload, TerminateSignal, hardout
from dnx_gentools.def_constants import TYPE_CHECKING, HOME_DIR, console_log
from dnx_gentools.def_typing import cast, ModuleProtocol

from dnx_control.system.systemd import sysd_notify_stopping

from dnx_cli.utils.shell_colors import text, styles
from dnx_cli.utils.structure import SERVICE_LIST, COMMANDS, check_command, check_module
from dnx_cli.utils.io import dnx_run_v, sprint
from dnx_cli.utils.sysctl import sysctl_command, sysctl_status, journalctl_brief

if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Optional

    from dnx_cli.utils.structure import Module


_AUTOLOADER = False

# style aliases
BOLD = styles.bold

def main() -> None:
    command, mod, module = parse_args()

    if (command == 'help'):
        help_command()

    elif command in ['start', 'stop', 'restart', 'status']:
        service_command(mod, command)

    elif (command == 'journal'):
        journalctl_command(mod)

    elif (command == 'install'):
        install_command()

    elif (command == 'update'):
        update_command(mod)

    elif (command == 'compile'):
        compile_command(mod)

    elif (command == 'cli'):
        run_cli(mod, module.path)

    elif (command == 'dev'):
        if (module.bash_cmd):
            run(module.bash_cmd, shell=True)

        else:
            run_cli(mod, module.path)

    elif (command == 'modstat'):
        print(text.yellow('Deprecated. Use "dnx status all" instead.'))
        service_command('all', command)

    else:
        sprint(text.lightgrey(f'<dnx> ') + text.red(f'missing command logic for -> mod={mod} command={command}'))

# using environ var to notify imported module to initialize and run.
# this was done because a normal function was causing issues with the linter thinking a ton of stuff was not defined.
# this could probably be done better.
# TODO: see if can be done better
def run_cli(mod: str, mod_loc: str) -> None:
    # needed due to previous naming and calling conventions
    mod_name = 'autoloader' if mod in ['system', 'signatures'] else mod

    os.environ['INIT_MODULE'] = mod_name
    os.environ['HOME_DIR'] = HOME_DIR

    # env = MODULES[mod].get('environ')
    # if (env):
    #     os.environ[env[0]] = env[1]

    mod_path = '/'.join([HOME_DIR, *mod_loc.split('.')[:2]])

    sys.path.insert(0, HOME_DIR)
    # inserting the module path into the system path so intra-module imports can be done locally
    sys.path.insert(0, mod_path)

    # idea:: make a custom exception for HOT RELOADING.
    #  if the downstream module raises, then we can reload / re import via importlib and re run it as normal.
    #  - putting this code block in a while loop should allow this to be done pretty easily.
    dnx_mod: Optional[ModuleProtocol] = None
    try:
        dnx_mod = cast(ModuleProtocol, importlib.import_module(mod_loc))
    except ImportError as ie:
        sprint(text.lightgrey(f'{mod} ') + text.red(f'import error -> {ie}'))

    except KeyboardInterrupt:
        sprint(text.lightgrey(f'{mod} ') + text.yellow('(cli) ') + text.red('interrupted!'))

    except SystemExit:
        sprint(text.lightgrey(f'{mod} ') + text.yellow('(cli) ') + text.red('exited!'))

    except TerminateSignal:
        console_log(f'Process is finalizing SIGTERM request.')
        sysd_notify_stopping()

    while dnx_mod:
        try:
            dnx_mod.run()
        except ModuleReload:
            importlib.reload(dnx_mod)
            continue

        except KeyboardInterrupt:
            sprint(text.lightgrey(f'{mod} ') + text.yellow('(cli) ') + text.red('interrupted!'))

        except SystemExit:
            sprint(text.lightgrey(f'{mod} ') + text.yellow('(cli) ') + text.red('exited!'))

        except TerminateSignal:
            console_log(f'Process is finalizing SIGTERM request.')
            sysd_notify_stopping()

        break

    # this will make sure there are no dangling processes or threads on exit.
    hardout()

def parse_args() -> tuple[str, str, Module]:
    global _AUTOLOADER

    cmd: str = get_index(1)
    mod: str = get_index(2)

    module_required = check_command(cmd, mod)

    module = check_module(mod) if module_required else None

    # index of first argument to be passed through to the specified module
    pt_arg_start = 2 if cmd in ['install'] else 3

    # branch override can be used to prevent the system from forcing a checkout of the release branches.
    arg_list = []
    for arg in sys.argv[pt_arg_start:]:
        if arg.startswith('-B'):
            os.environ['BRANCH_OVERRIDE'] = arg[2:]
        else:
            arg_list.append(arg)

    os.environ['PASSTHROUGH_ARGS'] = ','.join(arg_list)

    if ('_autoloader_' in os.environ['PASSTHROUGH_ARGS']):
        _AUTOLOADER = True

    return cmd, mod, module

def get_index(idx: int, /) -> str:
    try:
        return sys.argv[idx].lower()
    except IndexError:
        return 'X'

def help_command() -> None:
    print('\n', text.blue('----------- ') + text.lightgrey(' | Commands | ') + text.blue('-----------'))

    convert_bool = {True: text.red('yes'), False: text.green('no')}
    # iterate over COMMANDS dict and print each to a line, adding : in between
    # I want to replace priv with privilege for readability, will experiment.
    # TODO: better way to do this?
    for cmd, opts in COMMANDS.items():
        description = opts.description
        cmd_opts = {
            'description': text.yellow(description, style=None),
            'priv_required': convert_bool[opts.priv_required],
            'module_required': convert_bool[opts.module_required],
            'module_list': f'[ {" ".join(opts.module_list) if opts.module_list else ""} ]'
        }
        if (not description):
            cmd_opts.pop('description')

        print(text.lightgrey(f'{cmd}: '))
        for opt, val in cmd_opts.items():
            print('    ', f'{opt.ljust(14)}... {val}')

def service_command(mod: str, cmd: str) -> None:
    results: list[bool] = []
    ctl_switch = {
        'status':  partial(sysctl_status, brief=mod == 'all'),
        'start':   partial(sysctl_command, cmd='start'),
        'restart': partial(sysctl_command, cmd='restart'),
        'stop':    partial(sysctl_command, cmd='stop')
    }

    if (mod == 'all'):
        # =================================
        # OUTPUT - Justified left<==>right
        # =================================
        # dnx-cfirewall   => down (code=4)
        services_banner = text.lightblue('\n'.join([
            ' __..___.__ .  .._. __ .___ __.',
            '(__ [__ [__)\  / | /  `[__ (__ ',
            '.__)[___|  \ \/ _|_\__.[___.__)'
        ]))
        print(services_banner)

    services = SERVICE_LIST if mod == 'all' else [mod]
    for svc in services:

        results.append(ctl_switch[cmd](svc))

    # single service check will skip the summary.
    if (mod != 'all' or cmd != 'status'): return

    if down_ct := len([b for b in results if not b]):
        print(
            text.red(f'\nALERT! ') + text.lightgrey(f'[{down_ct}] failed service(s) detected! ')
        )
        print(text.lightgrey('Check journal for more details.\n'))

    else:
        print(text.green(f'\nAll services running!\n'))

def journalctl_command(mod: str) -> None:
    journalctl_brief(mod)

# function is for consistency even if it seems unnecessary
def install_command() -> None:
    run_cli('system', 'dnx_control.system.autoloader')

def compile_command(mod: str) -> None:
    file_path = f'{HOME_DIR}/dnx_profile/utils/compiler/{mod.replace("-", "_")}.py'
    try:
        dnx_run_v(f'sudo HOME_DIR={HOME_DIR} python3 {file_path} build_ext --inplace', shell=True)
    except CalledProcessError as cpe:
        if (_AUTOLOADER): raise

        sprint(text.lightgrey(f'{mod} compile has') + text.red(' failed ') + text.lightgrey(f'-> {cpe}!'))

    else:
        sprint(text.lightgrey(f'{mod} compile has') + text.green(' succeeded') + text.lightgrey('!'))

def update_command(mod: str) -> None:
    # update dnx system + signatures.
    # passthrough arguments and defaults:
    #   v: int = 0
    #   verbose: int = 0
    #   packages: int = 0
    #   iptables: int = 0
    if (mod == 'system'):
        # setting the env var to notify autoloader to run the update process instead of full installation.
        os.environ['_SYSTEM_UPDATE'] = 'True'

        run_cli('system', 'dnx_control.system.autoloader')

    # only update signatures, not the entire system, unless remote signatures are not compatible with the currently
    # installed system version.
    elif (mod == 'signatures'):
        os.environ['_SIGNATURE_UPDATE'] = 'True'

        run_cli('system', 'dnx_control.system.autoloader')

if (__name__ == '__main__'):
    main()
