#!/usr/bin/python3

if (__name__ == '__main__'):
    import __init__

import sqlite3

from dnx_gentools.def_constants import *

__all__ = ('DBConnector',)

NO_ROUTINE = [None, None]

print('db_conn', __name__)


class _DBConnector:
    DB_PATH = f'{HOME_DIR}/dnx_system/data/dnxfirewall.sqlite3'

    __slots__ = (
        '_Log', '_table', '_data_written',

        '_conn', '_cur',

        '_routines_get'
    )

    # format: {'func name': [routine_type('write/query/clear'), ref(function pointer)]}
    _routines = {}

    @classmethod
    def register(cls, routine_name, *, routine_type):
        '''register routine with database connector that can be called with the "execute" method.'''

        name_in_use = cls._routines.get(routine_name)
        if (name_in_use):
            raise FileExistsError(f'routing with name {routine_name} already exists')

        def wrapper(func_ref):

            registered_routine = staticmethod(func_ref)

            setattr(cls, routine_name, registered_routine)

            cls._routines[routine_name] = [routine_type, registered_routine]

        return wrapper

    # NOTE: if Log is not sent in, calling any method configured to log will error out, but likely not cause
    # significant impact as it is covered by the context.
    def __init__(self, Log=None, *, table=None):
        self._Log = Log

        self._table = table

        self._data_written = False

        self._routines_get = self._routines.get

    def __enter__(self):
        self._conn = sqlite3.connect(self.DB_PATH)
        self._cur = self._conn.cursor()

        return self

    def __exit__(self, exc_type, exc_val, traceback):
        if (self._data_written):
            self._conn.commit()

        self._conn.close()

        # should be logged through the logging system. Worst case use simple log if full logging is not easily in reach.
        if (exc_type):
            try:
                self._Log.error(f'error while writing to database: {exc_val}')
            except:
                write_log(f'error while writing to database: {exc_val}')

        return True

    def execute(self, routine_name, *args, **kwargs):

        routine_type, routine = self._routines_get(routine_name, NO_ROUTINE)
        if (not routine):
            raise FileNotFoundError(f'Database routine {routine_name} not registered.')

        if (routine_type in ['write', 'clear']):
            self._data_written = routine(self._cur, *args, **kwargs)

        elif (routine_type == 'query'):
            return routine(self._cur, *args, **kwargs)

        else:
            ValueError(f'routine type {routine_type} invalid.')

    def commit_entries(self):
        self._conn.commit()

    def blocked_cleaner(self, table):
        expire_threshold = int(fast_time()) - FIVE_MIN
        self._cur.execute(f'delete from {table} where timestamp < {expire_threshold}')

        self._data_written = True

    def table_cleaner(self, log_length, table):
        expire_threshold = int(fast_time()) - (ONE_DAY * log_length)
        self._cur.execute(f'delete from {table} where last_seen < {expire_threshold}')

        self._data_written = True

    def create_db_tables(self):
        # dns proxy main
        self._cur.execute(
            'create table if not exists dnsproxy '
            '(src_ip text not null, domain text not null, '
            'category text not null, reason text not null, '
            'action text not null, count int4 not null, '
            'last_seen int4 not null)'
        )

        # ip proxy main
        self._cur.execute(
            'create table if not exists ipproxy '
            '(local_ip text not null, tracked_ip text not null, '
            'category text not null, direction text not null, '
            'action text not null, last_seen int4 not null)'
        )

        # ips/ids main
        self._cur.execute(
            'create table if not exists ips '
            '(src_ip not null, protocol not null, '
            'attack_type not null, action not null, '
            'last_seen int4 not null)'
        )

        # infected clients
        self._cur.execute(
            'create table if not exists infectedclients '
            '(mac text not null, ip_address text not null, '
            'detected_host text not null, reason text not null, '
            'last_seen int4 not null)'
        )

        # ip proxy - geolocation
        #( 01,2021 | CHINA | 10 | 1)
        self._cur.execute(
            'create table if not exists geolocation '
            '(month not null, country not null, '
            'direction not null, '
            'blocked int4 not null, '
            'allowed int4 not null)'
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
            'value not null, description text not null)'
        )

# NOTE: psql connector is too out of spec, so it will be disabled until a later time.
#if (SQL_VERSION == 0):
DBConnector = _DBConnector

#else:
#    from dnx_routines.database.ddb_connector_psql import DBConnector

import dnx_routines.database.ddb_routines # routines will be set within DBConnector class

if __name__ == '__main__':
    # NOTE: CREATE THE TABLES
    #   only used on self deployments where system is running already and the tables need to be created
    with DBConnector() as FirewallDB:
        FirewallDB.create_db_tables()
