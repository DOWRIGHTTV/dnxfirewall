#!/usr/bin/python3

from __future__ import annotations

import importlib
import sqlite3

from dnx_gentools.def_constants import module_import_callout

module_import_callout(__file__)

from dnx_gentools.def_exceptions import dnx_assert
from dnx_gentools.def_constants import TYPE_CHECKING, HOME_DIR, ONE_DAY, FIVE_MIN, fast_time, console_log
from dnx_gentools.def_enums import DB_MODE, DB_MODE_NONE, DB_MODE_READ, DB_MODE_WR_CL

if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Optional, ClassVar, Callable_T

    from dnx_routines.logging import LogHandler_T

    from sqlite3 import Cursor, Connection

    ROUTINE_MAP: dict[str, list[DB_MODE, Callable_T]]


__all__ = (
    'DBConnector',
)

NO_ROUTINE = (None, None)


class DBConnector:
    '''Database connector class for sqlite3.

    .init_routines(DB_MODE) is required to set the running mode of the context per process.
        - available modes: DB_MODE_NONE, DB_MODE_READ, DB_MODE_WR_CL
        - routines will be imported from database.ddb_routines and passed through a filtered for registration.
    '''
    DB_PATH: ClassVar[str] = f'{HOME_DIR}/dnx_profile/data/dnxfirewall.sqlite3'

    _valid_tables_cleaning: ClassVar[tuple[str, str, str, str]] = ('dnsproxy', 'ipproxy', 'ips', 'infectedclients')

    _routines: ClassVar[ROUTINE_MAP] = {}
    _mode:     ClassVar[int] = DB_MODE_NONE

    # _log: LogHandler_T
    # _table: str
    _readonly: bool
    _connect:  bool
    _data_written: bool

    _conn: Optional[Connection]
    _cur:  Optional[Cursor]

    failed: bool

    __slots__ = (
        '_log', '_table', '_data_written',
        '_conn', '_cur', '_readonly', '_connect',
        '_routines_get', 'failed',
    )

    @classmethod
    def init_routines(cls, mode: DB_MODE) -> None:
        '''initialize database routines based on mode.

        initialization is only needed when importing the DBConnector class from external modules.
        '''
        cls._mode = mode

        importlib.import_module('dnx_routines.database.ddb_routines')

    @classmethod
    def register(cls, routine_name: str, *, routine_type: DB_MODE) -> Callable_T:
        '''register routine with database connector that can be called initiated with the "execute" method.
        '''
        name_in_use: list = cls._routines.get(routine_name, [])

        dnx_assert(not name_in_use, f'routine with name {routine_name} already exists')

        def registration(func_ref: Callable_T):

            if (routine_type & cls._mode):

                # converting routine function to static method
                registered_routine = staticmethod(func_ref)

                # defines a static method as the db connector class attribute
                setattr(cls, routine_name, registered_routine)

                # storing routines in class dictionary to make it easier to associate name, type and function ref.
                # note: getattr is used to store the staticmethod reference as it's bounded to the class.
                cls._routines[routine_name] = [routine_type, getattr(cls, routine_name)]  # note: type issue fine here.

                console_log(f'DB ROUTINE REGISTERED [{routine_type.name}] -> {routine_name}')

            # returning callable to make the decorator happy. the function will be called via reference and not by name.
            def wrapper(*args, **kwargs):

                func_ref(args, **kwargs)

            return wrapper

        return registration

    # NOTE: if Log is not sent in, calling any method configured to log will error out, but likely not cause
    #  significant impact as it is covered by the context (always returns True).
    def __init__(self, log: LogHandler_T = None, *, table: str = None, readonly: bool = False, connect: bool = True):

        self._log = log
        self._table = table

        self._readonly = readonly
        self._connect = connect

        self._conn = None
        self._cur  = None

        self._data_written = False

        self._routines_get = self._routines.get

        # used to notify a calling process whether a failure occurred within the context.
        # this does not distinguish if multiple calls/returns are done.
        # note: only usable if class is initialized prior to entering the context.
        self.failed = False

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

    def execute(self, routine_name: str, *args, **kwargs):
        routine_type, routine = self._routines_get(routine_name, NO_ROUTINE)

        dnx_assert(routine, f'Database routine {routine_name} not registered.')

        if (routine_type & DB_MODE_WR_CL):
            dnx_assert(not self._readonly, 'The database context cannot update the database in readonly mode.')

            self._data_written = routine(self._cur, *args, **kwargs)

        elif (routine_type & DB_MODE_READ):
            return routine(self._cur, *args, **kwargs)

        else:
            raise ValueError(f'routine type {routine_type} invalid.')

    def commit_entries(self):
        self._conn.commit()

    def blocked_cleaner(self) -> None:
        expire_threshold = fast_time() - FIVE_MIN
        self._cur.execute(f'delete from blocked where timestamp < {expire_threshold}')

        self._data_written = True

    def table_cleaner(self, log_length: int, table: str) -> None:
        dnx_assert(table in self._valid_tables_cleaning, f'invalid table specified for cleaning: {table}')

        expire_threshold = fast_time() - (log_length * ONE_DAY)
        self._cur.execute(f'delete from {table} where last_seen < {expire_threshold}')

        self._data_written = True

    def create_db_tables(self) -> None:
        # dns proxy main
        self._cur.execute(
            """
            create table if not exists dnsproxy
            (
                src_ip      int4 not null,
                domain      text not null,
                category    text not null,
                reason      text not null,
                action      text not null,
                count       int4 not null,
                last_seen   int4 not null
            )
            """
        )

        # ip proxy main
        self._cur.execute(
            """
            create table if not exists ipproxy 
            (
                local_ip    int4 not null,
                tracked_ip  int4 not null,
                category    text not null,
                direction   text not null, 
                action      text not null,
                last_seen   int4 not null
            )
            """
        )

        # ips/ids main
        self._cur.execute(
            """
            create table if not exists ips 
            (
                src_ip      int4 not null,
                protocol    text not null,
                attack_type text not null,
                action      text not null, 
                last_seen   int4 not null
            )
            """
        )

        # infected clients
        self._cur.execute(
            """
            create table if not exists infectedclients 
            (
                mac             text not null,
                ip_address      int4 not null,
                detected_host   text not null,
                reason          text not null, 
                last_seen       int4 not null
            )
            """
        )

        # ip proxy - geolocation
        # (01,2021 | CHINA | 10 | 1)
        self._cur.execute(
            """
            create table if not exists geolocation 
            (
                month       text not null,
                country     text not null,
                direction   text not null, 
                blocked     int4 not null,
                allowed     int4 not null
            )
            """
        )

        # dns proxy - blocked clients (for serving webui block page)
        self._cur.execute(
            """
            create table if not exists blocked 
            (
                src_ip      not null,
                domain      not null, 
                category    not null,
                reason      not null,
                timestamp   int4 not null
            )
            """
        )

        # webui objects
        self._cur.execute(
            """
            create table if not exists config_objects 
            (
                name        text not null,
                type        text not null,
                value       text not null,
                description text not null
            )
            """
        )

        # messanger
        self._cur.execute(
            """
            create table if not exists messenger 
            (
                msg_id      text not null,
                sender      text not null,
                recipients  text not null, 
                multi       int4 not null,
                sent_at     int4 not null,
                message     text not null, 
                expiration  int4 not null
            )
            """
        )
