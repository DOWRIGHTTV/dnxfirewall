#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, Type

__all__ = (
    'DBConnector',

    # Types
    'DBConnector_T'
)

if (TYPE_CHECKING):
    from ddb_connector_sqlite import DBConnector

    DBConnector_T = Type[DBConnector]


