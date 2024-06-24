from __future__ import annotations

import os
import sys
import time
import itertools
import threading

from dnx_gentools.def_constants import TYPE_CHECKING

from dnx_cli.utils.shell_colors import text

if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Optional, Callable


__all__ = (
    'create_progress_bar', 'Spinner',
)


# ----------------------------
# PROGRESS BAR
# ----------------------------
PROGRESS_BAR_SIZE: int = 30
def _clear_line() -> None:
    '''clears the current line in the terminal.

        useful for writes that are not on a new line to prevent previous character overflow.
    '''
    sys.stdout.write(' ' * os.get_terminal_size().columns + '\r')

    sys.stdout.flush()

def create_progress_bar(num_tasks: int):

    current_progress = 0

    def progress(desc: str, *, progress_override: int = 0):
        '''prints a progress bar to the terminal.
        '''
        nonlocal current_progress

        current_progress = progress_override if progress_override else current_progress

        # this will ensure completed count does not exceed total count when rendering.
        # this would only happen if I miscalculated the total count somewhere. (happens too often LOL :/)
        if (current_progress > num_tasks):
            current_progress = num_tasks

        # calculating bar %
        ratio: float = current_progress / num_tasks
        filled_len: int = int(PROGRESS_BAR_SIZE * ratio)

        # COLORIZING COMPLETION STATUS BAR
        # --------------------------------------------------------------------
        perc = f'{int(100 * ratio)}'.rjust(3)
        filled = '#' * filled_len
        if (ratio < .34):
            progress_fill = text.red(filled, style=None)
            percentage = text.red(perc, style=None)

        elif (ratio < .67):
            progress_fill = text.orange(filled, style=None)
            percentage = text.orange(perc, style=None)

        elif (ratio < 1):
            progress_fill = text.green(filled, style=None)
            percentage = text.yellow(perc, style=None)

        else:
            progress_fill = text.green(filled, style=None)
            percentage = text.green(perc, style=None)

        progress_fill += text.lightgrey('=' * (PROGRESS_BAR_SIZE - filled_len))

        # RENDERING UPDATED TIMESTAMP, BAR, DESCRIPTION
        # --------------------------------------------------------------------
        _clear_line()

        # 1. timestamp, 2. x/total | 3. | [##########] 4. 100% | 5. | description
        bar  = text.lightgrey(f'{time.strftime("%H:%M:%S")}| ')
        bar += text.yellow(f'{current_progress}'.rjust(2), style=None) + text.lightgrey(f'/{num_tasks} |')
        bar += text.lightgrey(f'| [', style=None) + progress_fill + text.lightgrey(f'] ', style=None)
        bar += percentage + text.lightgrey('% |', style=None)
        bar += text.yellow(f'| {desc}\r')

        sys.stdout.write(bar)

        # allows for rendering bar without moving the completion %.
        if (desc):
            current_progress += 1

        # prevents bar from being overwritten once complete
        if (filled_len == PROGRESS_BAR_SIZE):
            sys.stdout.write('\n')

        # forces current stdout buffer to be written to terminal
        sys.stdout.flush()

    return progress


class Spinner:
    '''context manager for displaying a spinner while a block of code is running.
    '''
    animation = itertools.cycle(r'-\|/')
    cycle_rate = 0.25

    def __init__(self, msg: str) -> None:
        self.msg = msg

    def __enter__(self) -> Spinner:
        self.start = time.time()

        self.animate = threading.Event()
        self.animate.set()

        self._spin_thread = threading.Thread(target=self._spin)
        self._spin_thread.start()

        return self

    def __exit__(self, exc_type, exc_value, exc_traceback) -> None:
        self.animate.clear()

        self._spin_thread.join()

    def _spin(self) -> None:
        while self.animate.is_set():
            sys.stdout.write(f'\r{self.msg} {next(self.animation)}')

            time.sleep(self.cycle_rate)
