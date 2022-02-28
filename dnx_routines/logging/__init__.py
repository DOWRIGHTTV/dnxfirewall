#!/usr/bin/env python3

from __future__ import annotations

from dnx_routines.logging.log_main import *
from dnx_routines.logging.log_client import *

from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from log_client import *
    from log_main import *
