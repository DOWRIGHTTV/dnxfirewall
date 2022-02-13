#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from database.ddb_connector_sqlite import *
    from logging.log_client import LogHandler
