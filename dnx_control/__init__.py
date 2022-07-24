#!/usr/bin/env python3

from __future__ import annotations

# ================
# RUNTIME IMPORTS
# ================
from dnx_gentools.def_constants import INITIALIZE_MODULE

if INITIALIZE_MODULE('syscontrol'):
    __all__ = ('run',)

    from dnx_routines.logging import Log

    Log.run(name='system')

    from dnx_control.control.ctl_control import SystemControl


def run():
    SystemControl.run()
