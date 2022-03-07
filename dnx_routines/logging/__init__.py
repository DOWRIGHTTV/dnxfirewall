#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, Type

if (TYPE_CHECKING):
    from log_client import *
    from log_main import *

    # ======
    # TYPES
    # ======
    LogHandler_T = Type[LogHandler]

# ================
# RUNTIME IMPORTS
# ================
from dnx_routines.logging.log_main import *
from dnx_routines.logging.log_client import *
