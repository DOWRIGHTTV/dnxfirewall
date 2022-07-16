#!/usr/bin/python3

from __future__ import annotations

import sqlite3
import importlib

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *

if (TYPE_CHECKING):
    from typing import TypeAlias

    from dnx_routines.logging import LogHandler_T
    from dnx_routines.database import DBConnector_T

    NO_ROUTINE: tuple[None, None]


__all__ = (
    'DBConnector',
)

NO_ROUTINE = (None, None)


class _DBConnector:
    DB_PATH: ClassVar[str] = f'{HOME_DIR}/dnx_system/data/dnxfirewall.sqlite3'

    __slots__ = (
        '_log', '_table', '_data_written',
        '_conn', '_cur', '_readonly', '_connect',
        '_routines_get', 'failed',
    )

    # format: {'func name': [routine_type('write/query/clear'), ref(function pointer)]}
    _routines: ClassVar[dict[str, list[str, Callable_T]]] = {}

    @classmethod
    def register(cls, routine_name: str, *, routine_type: str) -> Callable_T:
        '''register routine with database connector that can be called initiated with the "execute" method.'''

        name_in_use: list = cls._routines.get(routine_name, None)
        if (name_in_use):
            raise FileExistsError(f'routine with name {routine_name} already exists')

        def registration(func_ref: Callable_T):

            # print(f'FUNC_REF {func_ref}')
            # converting routine function to static method
            registered_routine = staticmethod(func_ref)

            # print(f'REGISTERED FUNC_REF {registered_routine}')
            # define static method as db connector class attribute
            setattr(cls, routine_name, registered_routine)

            # storing routines in class dictionary to make it easier to associate name, type and function ref. getattr
            # is used to store the staticmethod reference as it's bounded to the class.
            cls._routines[routine_name] = [routine_type, getattr(cls, routine_name)]

            # print(f'REGISTERED {routine_name}')

            # returning callable to make the decorator happy. the function will be called via reference and not by name.
            def wrapper(*args, **kwargs):

                func_ref(args, **kwargs)

            return wrapper

        # print(f'RETURNING REGISTRATION FOR {routine_name}')

        return registration

    # NOTE: if Log is not sent in, calling any method configured to log will error out, but likely not cause
    #  significant impact as it is covered by the context.
    def __init__(self, log: LogHandler_T = None, *, table: str = None, readonly: bool = False, connect: bool = True):

        # used to notify a calling process whether a failure occurred within the context.
        # this does not distinguish if multiple calls/returns are done.
        self.failed: bool = False

        self._log: LogHandler_T = log
        self._table: str = table
        self._readonly: bool = readonly
        self._connect: bool = connect

        self._conn = None
        self._cur  = None

        self._data_written: bool = False

        self._routines_get: Callable_T = self._routines.get

    def __enter__(self) -> DBConnector:
        if (self._connect):
            self._conn = sqlite3.connect(self.DB_PATH)
            self._cur = self._conn.cursor()

        return self

    def __exit__(self, exc_type, exc_val, traceback) -> bool:
        if (self._data_written):
            self._conn.commit()

        if (exc_type):
            self.failed = True
            try:
                self._log.error(f'database failure: {exc_val}')
            except:
                console_log(f'database failure: {exc_val}')

        self._conn.close()

        return True

    def execute(self, routine_name: str, *args, **kwargs) -> list:

        routine_type, routine = self._routines_get(routine_name, NO_ROUTINE)
        if (not routine):
            raise FileNotFoundError(f'Database routine {routine_name} not registered.')

        if (routine_type in ['write', 'clear']):
            self._data_written = routine(self._cur, *args, **kwargs)

        elif (routine_type == 'query'):
            return routine(self._cur, *args, **kwargs)

        else:
            raise ValueError(f'routine type {routine_type} invalid.')

    def commit_entries(self):
        self._conn.commit()

    def blocked_cleaner(self, table: str) -> None:
        expire_threshold = int(fast_time()) - FIVE_MIN
        self._cur.execute(f'delete from {table} where timestamp < {expire_threshold}')

        self._data_written = True

    def table_cleaner(self, log_length: int, table: str) -> None:
        expire_threshold = int(fast_time()) - (ONE_DAY * log_length)
        self._cur.execute(f'delete from {table} where last_seen < {expire_threshold}')

        self._data_written = True

    def create_db_tables(self) -> None:
        # dns proxy main
        self._cur.execute(
            'create table if not exists dnsproxy '
            '(src_ip int4 not null, domain text not null, '
            'category text not null, reason text not null, '
            'action text not null, count int4 not null, '
            'last_seen int4 not null)'
        )

        # ip proxy main
        self._cur.execute(
            'create table if not exists ipproxy '
            '(local_ip int4 not null, tracked_ip int4 not null, '
            'category text not null, direction text not null, '
            'action text not null, last_seen int4 not null)'
        )

        # ips/ids main
        self._cur.execute(
            'create table if not exists ips '
            '(src_ip int4 not null, protocol text not null, '
            'attack_type text not null, action text not null, '
            'last_seen int4 not null)'
        )

        # infected clients
        self._cur.execute(
            'create table if not exists infectedclients '
            '(mac text not null, ip_address int4 not null, '
            'detected_host text not null, reason text not null, '
            'last_seen int4 not null)'
        )

        # ip proxy - geolocation
        # (01,2021 | CHINA | 10 | 1)
        self._cur.execute(
            'create table if not exists geolocation '
            '(month text not null, '
            'country text not null, direction not null, '
            'blocked int4 not null, allowed int4 not null)'
        )

        # dns proxy - blocked clients (for serving webui block page)
        self._cur.execute(
            'create table if not exists blocked '
            '(src_ip not null, domain not null, '
            'category not null, reason not null, '
            'timestamp int4 not null)'
        )

        # webui objects
        self._cur.execute(
            'create table if not exists config_objects '
            '(name text not null, type text not null, '
            'value text not null, description text not null)'
        )


# NOTE: psql connector is too out of spec, so it will be disabled until a later time.
# if (SQL_VERSION == 0):
DBConnector: DBConnector_T = _DBConnector
# else:
#    from dnx_routines.database.ddb_connector_psql import DBConnector

# routines will be registered with DBConnector class
importlib.import_module('dnx_routines.database.ddb_routines')
