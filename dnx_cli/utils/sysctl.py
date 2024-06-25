from __future__ import annotations

import time
from subprocess import check_output, CalledProcessError

from dnx_gentools.def_constants import nl_join

from dnx_cli.utils.shell_colors import text
from dnx_cli.utils.ux import Spinner
from dnx_cli.utils.io import dnx_run


WAIT_TIME = 2
SERVICE_JUSTIFY = 16

def sysctl_command(mod: str, *, cmd: str) -> None:
    svc = f'dnx-{mod.replace("_", "-")}'

    with Spinner(f'Attempting [{cmd.upper()}] on {mod}:') as spinner:
        try:
            dnx_run(f'sudo systemctl {cmd} {svc}', shell=True)
        except CalledProcessError:
            pass
        else:
            time.sleep(WAIT_TIME)

            try:
                out = check_output(f'systemctl status {svc}', shell=True, text=True).splitlines()
            except CalledProcessError as cpe:
                out = cpe.output.splitlines()

        spinner.animate.clear()

        active = out[2].split()
        if (cmd == 'stop'):
            result = text.yellow('inactive') if active[1] == 'inactive' else text.red(active[1])

        else:
            result = text.green('active') if active[1] == 'active' else text.red('failed')

        print(f'\rAttempting [{cmd.upper()}] on {mod}: {result}')

def sysctl_status(mod: str, brief: bool = False) -> bool:
    svc = f'dnx-{mod.replace("_", "-")}'
    status = text.red('down')

    try:
        out = check_output(f'systemctl status {svc}', shell=True, text=True).splitlines()
    except CalledProcessError as cpe:
        out = cpe.output.splitlines()

    warning = '' if not out[0].startswith('Warning:') else out.pop(0)

    title  = out[0].split()
    loaded = out[1]  # .split()
    active = out[2].split()

    try:
        main_pid = out[3]  # .split()
        memory = out[5]  # .split()
    except:
        main_pid = ''
        memory = ''

    if (active[1] == 'active'):
        title[0]  = text.green(title[0])
        active[1] = text.green(active[1])
        active[2] = text.green(active[2])
        status = text.green('up')

    elif (active[1] == 'activating'):
        title[0]  = text.yellow(title[0])
        active[1] = text.yellow(active[1])

    elif (active[1] == 'inactive'):
        title[0]  = text.lightgrey(title[0])
        active[1] = text.orange(active[1])

    elif (active[1] == 'failed'):
        title[0]  = text.red(title[0])
        active[1] = text.red(active[1])

    if (brief):
        print(text.darkgrey(f'{svc.ljust(SERVICE_JUSTIFY)} -> {status.rjust(4)}'))

    else:
        stats = [
            text.yellow(warning),
            f'{title[0]} {text.darkgrey(" ".join(title[1:]))}',
            text.lightgrey(loaded),
            f'{text.lightgrey(active[0].rjust(12))} {active[1]} {active[2]} {text.lightgrey(" ".join(active[3:]))}',
            text.lightgrey(main_pid),
            text.lightgrey(memory)
        ]

        print('=' * 32)
        print(f'{nl_join([x for x in stats if x])}')
        print('=' * 32)

    return status == text.green('up')