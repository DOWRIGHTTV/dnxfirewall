#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, Type

__all__ = (
    'LogHandler', 'Log',
    'direct_log', 'message', 'db_message', 'convert_level',
    'emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug', 'cli',

    'LogHandler_T',

    'LogService',
)

# ================
# RUNTIME IMPORTS
# ================
if (not TYPE_CHECKING):
    from dnx_routines.logging.log_main import *
    from dnx_routines.logging.log_client import *

# ================
# TYPING IMPORTS
# ================
else:
    from log_client import *
    from log_main import *

    # ======
    # TYPES
    # ======
    LogHandler_T = Type[LogHandler]
