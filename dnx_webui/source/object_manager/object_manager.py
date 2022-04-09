#!/usr/bin/env python3

import fcntl

from random import randint
from os import replace
from ast import literal_eval

from dnx_gentools.def_constants import HOME_DIR
from dnx_gentools.def_namedtuples import FW_OBJECT
from dnx_gentools.file_operations import acquire_lock, release_lock

from dnx_routines.configure.system_info import System

from dnx_webui.source.web_typing import Union

# FUNCTION ALIASES
FILE_LOCK = fcntl.flock
EXCLUSIVE_LOCK = fcntl.LOCK_EX
UNLOCK_LOCK = fcntl.LOCK_UN

# CONSTANTS
DATA_DIR = f'{HOME_DIR}/dnx_webui/data'

DISK_BUFFER = f'{DATA_DIR}/disk_buffer'

SYSTEM_DB = f'{DATA_DIR}/firewall_objects.db'
USER_DB   = f'{DATA_DIR}/usr/firewall_objects.db'

DB_LOCK = f'{DATA_DIR}/firewall_objects.lock'

BUILTIN_RANGE = (1, 9999)  # probably not necessary
USER_RANGE = (10000, 999999)

# ===============
# FORMAT STRINGS
# ===============
DB_START = '{'
DB_END   = '}'

TABLE_NEXT  = ' },'
TABLE_END   = ' }'

def db_obj(key: str, obj: Union[int, list]) -> str:
    '''
    int  > "999":69
    list > "999":["1","1","1"]
    '''
    return f" '{key}':{obj},"

def table_str(key: str, obj: str) -> str:
    '''"name":"999"
    '''
    return f"  '{key}':{obj},"

def table_list(key: str, obj: str) -> str:
    '''"999":["1","1","1"]
    '''
    return f"  '{key}':{obj},"

def table_start(key: str) -> str:
    '''
    TABLE_START = "objects":{
    '''
    return f"  '{key}':" + '{,'


class FWObjectManager:

    def __init__(self):
        # self.firewall_objects = {}
        self.db_changed: bool = False

        # os.chmod(self._disk_buffer, 0o660)

    def __enter__(self):
        self._db_lock = acquire_lock(DB_LOCK)

        self.user_database = self._load()

    def __exit__(self):
        if (self.db_changed):
            self._write()

        replace(DISK_BUFFER, USER_DB)
        release_lock(self._db_lock)

    @classmethod
    def get_objects(cls):
        with open(USER_DB) as obj_db:
            loaded_db = obj_db.read()

            return literal_eval(loaded_db.replace('\n', ''))

    def add(self, obj: FW_OBJECT, /):
        '''["9003", "icmp", "built-in", "service", 1, "icmp/0", "<commonly> Ping"]
        '''
        user_objects = self.user_database['objects']

        obj_id = f'{randint(*USER_RANGE)}'
        while obj_id in user_objects:
            obj_id = f'{randint(*USER_RANGE)}'

        new_object = [obj_id, obj.name, 'extended', obj.type, obj.subtype, obj.value, obj.description]

        user_objects[obj_id] = new_object

    def update(self, obj: FW_OBJECT, /) -> None:
        try:
            self.user_database['objects'][obj.id] = obj.db_format()
        except KeyError:
            pass  # log this error with LogHandler or return error

        else:
            self.user_database['ntoid'][obj.name] = obj.id

            self.db_changed = True

    def delete(self, obj_id: str) -> None:
        fw_object = self.user_database['objects'].pop(obj_id, None)
        if (not fw_object):
            pass  # LogHandler or return error

        self.user_database['ntoid'].pop(fw_object.name, None)

        self.db_changed = True

    # =================
    # DISK IO
    # =================
    def _load(self) -> dict:
        with open(USER_DB) as obj_db:
            loaded_db = obj_db.read()

            return literal_eval(loaded_db.replace('\n', ''))

    def _write(self) -> None:
        user_database = self._build_db()

        with open(DISK_BUFFER, 'w') as obj_db:
            obj_db.write(user_database)

    # =================
    # STRING FORMATTER
    # =================
    def _build_db(self) -> str:
        # OBJECT TABLE
        db_version = self.user_database['version'] + 1

        database = [
            DB_START, db_obj('date', System.date()), db_obj('version', db_version), table_start('objects')
        ]
        db_append = database.append

        # INDEX TABLE - NAME TO ID
        ntoid = [table_start('ntoid')]
        ntoid_append = ntoid.append

        # FORMATTING OBJECTS
        for obj in self.user_database['objects'].values():

            db_append(table_list(obj[0], obj[1]))
            ntoid_append(table_str(obj[1], obj[0]))

        # hack to strip the trailing comma on the last element in the list.
        database[-1] = database[-1][:-1]
        ntoid[-1] = ntoid[-1][:-1]

        db_append(TABLE_NEXT)

        database.extend(ntoid)

        db_append(TABLE_END)
        db_append(DB_END)

        return '\n'.join(database)
