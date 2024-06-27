from __future__ import annotations

import os
import sys
import time
import importlib
import traceback

from functools import partial
from subprocess import run, DEVNULL

from dnx_gentools.def_exceptions import TerminateSignal
from dnx_gentools.def_constants import HOME_DIR, console_log, hardout, hardout_errno
from dnx_control.system.systemd import sysd_notify_stopping

from dnx_cli.utils.shell_colors import text

ERROR_SHOW_TIME = .33
LINEBREAK: str = text.lightblue('-' * 32)

dnx_run = partial(run, check=True, stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL)
dnx_run_v = partial(run, check=True, stdin=DEVNULL)

def line_print(sep: str = '-'): print(text.lightblue(f'{sep}' * os.get_terminal_size().columns))
def title_print(s: str, /) -> None: line_print(); print(s); line_print()

def flash_input_error(error: str, space_ct: int) -> None:
    # moves cursor up one space in the terminal
    sys.stdout.write('\033[1A')

    sys.stdout.write(f'\033[{space_ct}C')
    sys.stdout.write(text.orange(f'{error}\r', style=None))

    time.sleep(ERROR_SHOW_TIME)

    sys.stdout.write(f'{" " * os.get_terminal_size().columns}\r')

def ts_print(s: str, /) -> None:
    '''setup print. includes timestamp before arg str.

    the passed in message will be automatically colorized.
    '''
    print(text.lightgrey(f'{time.strftime("%H:%M:%S")}| ') + text.yellow(f'{s}'))

def err_print(s: str, /) -> None:
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

    # idea:: make a custom exception for HOT RELOADING.
    #  if the downstream module raises, then we can reload / re import via importlib and re run it as normal.
    #  - putting this code block in a while loop should allow this to be done pretty easily.
    try:
        dnx_mod = importlib.import_module(mod_loc)
    except KeyboardInterrupt:
        sprint(text.lightgrey(f'{mod} ') + text.yellow('(cli) ') + text.red('interrupted!'))

    except SystemExit:
        sprint(text.lightgrey(f'{mod} ') + text.yellow('(cli) ') + text.red('exited!'))

    # note: uncaught exception handler is not set up at this point.
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
            console_log(f'Process is finalizing SIGTERM request.')
            sysd_notify_stopping()

    # this will make sure there are no dangling processes or threads on exit.
    hardout()
