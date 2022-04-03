#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

# ================
# RUNTIME IMPORTS
# ================
if (not TYPE_CHECKING):
    __all__ = (
        'LogHandler', 'Log',
        'direct_log', 'message', 'db_message', 'convert_level',
        'emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug', 'cli',

        'LogService',
    )

    from dnx_routines.logging.log_main import *
    from dnx_routines.logging.log_client import *

# ================
# TYPING IMPORTS
# ================
else:
    from typing import Type

    __all__ = (
        'LogHandler',

        'LogHandler_T',

        'LogService',
    )

    from log_client import *
    from log_main import *

    # ======
    # TYPES
    # ======
    LogHandler_T = Type[LogHandler]
