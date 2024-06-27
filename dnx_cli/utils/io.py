from __future__ import annotations

import os
import sys
import time

from functools import partial
from subprocess import run, DEVNULL

from dnx_gentools.def_constants import hardout

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
