#!/usr/bin/env python3

from __future__ import annotations

# ================
# RUNTIME IMPORTS
# ================
from dnx_gentools.def_constants import INITIALIZE_MODULE
def run():
    LogService.run()


if INITIALIZE_MODULE('logging'):
    __all__ = (
        'LogHandler', 'Log',
        'direct_log', 'message', 'db_message', 'convert_level',
        # 'emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug', 'cli',

        'LogService',
    )

    from dnx_routines.logging.log_main import LogService
    from dnx_routines.logging.log_client import *

    Log.run(name='system')

# ================
# TYPING IMPORTS
# ================
from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    # from typing import Type, TypeAlias

    __all__ = (
        'LogHandler', 'LogHandler_T', 'LogService',
    )

    from log_client import *
    from log_main import *

    # ======
    # TYPES
    # ======
    # LogHandler_T: TypeAlias = Type[_LogHandlerBase]
