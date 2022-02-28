#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, Type

if (TYPE_CHECKING):
    from logging import *

    from database import *

    # this is being a pain in the ass
    from logging.log_client import _log_handler

    _LogHandler = _log_handler()
    LogHandler_T = Type[_LogHandler]
