from __future__ import annotations

import os
import sys
import importlib
import traceback

from functools import partial
from subprocess import run, DEVNULL

from dnx_gentools.def_exceptions import TerminateSignal
from dnx_gentools.def_constants import HOME_DIR, console_log, hardout, hardout_errno
from dnx_control.system.systemd import notify_stopping

from dnx_cli.utils.shell_colors import text


dnx_run = partial(run, check=True, stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL)
dnx_run_v = partial(run, check=True, stdin=DEVNULL)

def sprint(msg: str, /) -> None:
    '''prints a message to the terminal with an empty space above and below.
    '''
    print(f'\n{msg}\n')

# ;)
def sexit(msg: str, /) -> None:
    '''exits with a message to the terminal with an empty space above and below.
    '''
    exit(f'\n{msg}\n')

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

    try:
        dnx_mod = importlib.import_module(mod_loc)
    except KeyboardInterrupt:
        sprint(text.lightgrey(f'{mod} ') + text.yellow('(cli) ') + text.red('interrupted!'))

    except SystemExit:
        sprint(text.lightgrey(f'{mod} ') + text.yellow('(cli) ') + text.red('exited!'))

    except Exception as E:
        sprint(text.lightgrey(f'{mod} ') + text.yellow('(cli) ') + text.red(f'run failure. -> {E}'))
        traceback.print_exc()

        hardout_errno(1, f'module import failure -> {mod_loc}')

    else:
        try:
            dnx_mod.run()
        except KeyboardInterrupt:
            sprint(text.lightgrey(f'{mod} ') + text.yellow('(cli) ') + text.red('interrupted!'))

        except SystemExit:
            sprint(text.lightgrey(f'{mod} ') + text.yellow('(cli) ') + text.red('exited!'))

        except TerminateSignal:
            console_log(f'SIGTERM received.')
            notify_stopping()

        except Exception as E:
            sprint(text.lightgrey(f'{mod} ') + text.yellow('(cli) ') + text.red(f'run failure. -> {E}'))
            traceback.print_exc()

            hardout_errno(1, f'module run failure -> {mod_loc}')

    # this will make sure there are no dangling processes or threads on exit.
    hardout()
