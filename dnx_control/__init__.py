#!/usr/bin/env python3

from __future__ import annotations

# ================
# RUNTIME IMPORTS
# ================
from dnx_gentools.def_exceptions import TerminateSignal
from dnx_gentools.def_constants import INITIALIZE_MODULE

if INITIALIZE_MODULE('syscontrol'):
    __all__ = ('run',)

    from dnx_routines.logging.log_client import Log

    Log.run(name='system')

    from dnx_control.control.ctl_control import SystemControl


def run():
    try:
        SystemControl.run()
    except (KeyboardInterrupt, TerminateSignal):
        raise

    except Exception as e:
        Log.error(f'Error in ddb_main.run: {e}')
        raise
