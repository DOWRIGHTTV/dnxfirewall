#!/usr/bin/env python3

from __future__ import annotations

import fcntl
import os

from random import randint
from os import replace
from ast import literal_eval
from enum import IntEnum

from source.web_typing import TYPE_CHECKING, Union
from source.web_validate import ValidationError

from dnx_gentools.def_constants import HOME_DIR
from dnx_gentools.def_enums import GEO, DATA
from dnx_gentools.def_namedtuples import FW_OBJECT
from dnx_gentools.file_operations import config, acquire_lock, release_lock

from dnx_iptools.cprotocol_tools import iptoi
from dnx_iptools.protocol_tools import cidrtoi

from dnx_routines.configure.system_info import System
from dnx_routines.logging import Log


__all__ = (
    'FWObjectManager', 'USER_RANGE',
)

if (TYPE_CHECKING):
    ITER_FW_OBJECTS = list[list[str, str]]

# FUNCTION ALIASES
FILE_LOCK = fcntl.flock
EXCLUSIVE_LOCK = fcntl.LOCK_EX
UNLOCK_LOCK = fcntl.LOCK_UN

# CONSTANTS
DATA_DIR = f'{HOME_DIR}/dnx_webui/data'

DISK_BUFFER = f'{DATA_DIR}/usr/disk_buffer'

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

def db_skey_val(key: str, obj: Union[int, list]) -> str:
    '''
    int  > "999":69
    list > "999":["1","1","1"]
    '''
    return f" '{key}':{obj},"

def table_key_val(key: str, obj: str) -> str:
    '''
    "name":["1","1","1"]
    '''
    return f"  {key}:{obj},"

def table_skey_val(key: str, obj: str) -> str:
    '''
    "999":9001
    '''
    return f"  '{key}':{obj},"

def table_start(key: str) -> str:
    '''
    TABLE_START = "objects":{
    '''
    return f" '{key}':" + '{'


# ================
# RULE CONVERSION
# ================
INVALID_OBJECT = -1
MISSING_RULE = FW_OBJECT(0, 'none', 'none', 'none', 0, 'none', 'none')

proto_convert: dict[str, int] = {'icmp': 1, 'tcp': 6, 'udp': 17}
icon_map = {
    'tv': 'address', 'track_changes': 'address', 'vpn_lock': 'address',
    'dns': 'service', 'border_inner': 'zone'
}

class ADDR_OBJ(IntEnum):
    ADDRESS = 1
    NETWORK = 2
    RANGE   = 3
    GEO     = 6
    INV_ADDRESS = 11
    INV_NETWORK = 12
    INV_RANGE   = 13
    INV_GEO     = 16


class SVC_OBJ(IntEnum):
    SOLO  = 1
    RANGE = 2
    LIST  = 3

# TODO: this should be done one time/ precalculated
def convert_object(obj: FW_OBJECT, /) -> Union[int, list[int], list[list]]:
    if (obj.type == 'address'):

        if (obj.subtype in [ADDR_OBJ.ADDRESS, ADDR_OBJ.NETWORK, ADDR_OBJ.INV_ADDRESS, ADDR_OBJ.INV_NETWORK]):
            ip, netmask = obj.value.split('/')
            # type, int32 ip, int32 netmask
            return [obj.subtype, iptoi(ip), cidrtoi(netmask)]

        # type, int32 country code, null
        elif (obj.subtype == ADDR_OBJ.GEO):
            return [obj.subtype, GEO[obj.value.upper()].value, 0]

    elif (obj.type == 'service'):

        # type, int32 protocol, in32 port, null
        if (obj.subtype == SVC_OBJ.SOLO):
            proto, port = obj.value.split('/')

            return [obj.subtype, proto_convert[proto], int(port), 0]

        # type, int32 protocol, in32 start port, int32 end port
        elif (obj.subtype == SVC_OBJ.RANGE):
            proto, ports = obj.value.split('/')

            return [obj.subtype, proto_convert[proto], *[int(p) for p in ports.split('-')]]

        # list[ int32 type, list[ int32 protocol, int32 start port, int32 end port ]]
        elif (obj.subtype == SVC_OBJ.LIST):
            obj_list: list[Union[int, list]] = [obj.subtype]

            objs = obj.value.split(':')
            for obj in objs:

                proto, port = obj.split('/')
                p = port.split('-')

                if (len(p) == 1):
                    obj_list.append([proto_convert[proto], int(p[0]), int(p[0])])
                else:
                    obj_list.append([proto_convert[proto], int(p[0]), int(p[1])])

            return obj_list

    elif (obj.type == 'zone'):
        return int(obj.value)

    return INVALID_OBJECT


class FWObjectManager:

    def __init__(self, *, lookup: bool = False):
        self.lookup_set: bool = lookup
        self.db_changed: bool = False

        self.full_db = {}

    def __enter__(self) -> FWObjectManager:
        self._db_lock = acquire_lock(DB_LOCK)

        self.user_database = self._load()

        if (self.lookup_set):
            _, self.full_db = self.get_objects(full_db=True)

        return self

    def __exit__(self, exc_type, exc_val, traceback) -> bool:
        if exc_type:
            print(exc_val)

        if (self.db_changed):
            self._write()

            replace(DISK_BUFFER, USER_DB)

        release_lock(self._db_lock)

        if (exc_type is None):
            return True

        elif (exc_type is not ValidationError):
            Log.error(f'configuration manager error: {exc_val}')

            raise OSError('Configuration manager was unable to update the requested file.')

    @staticmethod
    def get_objects(full_db: bool = False):

        # BUILT-IN OBJECTS
        with open(SYSTEM_DB) as obj_db:
            string_db = obj_db.read()

        builtin_db = literal_eval(string_db.replace('\n', ''))

        # EXTENDED OBJECTS (USER)
        try:
            with open(USER_DB) as obj_db:
                string_db = obj_db.read()
        except FileNotFoundError:
            if (not full_db):
                return builtin_db['version'], builtin_db['objects']

            builtin_db['objects'] = {k: FW_OBJECT(*v) for k, v in builtin_db['objects'].items()}

            return builtin_db['version'], builtin_db

        user_db = literal_eval(string_db.replace('\n', ''))

        builtin_db['date'] = user_db['date']
        builtin_db['version'] = user_db['version']

        builtin_db['objects'].update(user_db['objects'])
        builtin_db['ntoid'].update(user_db['ntoid'])

        if (not full_db):
            return builtin_db['version'], builtin_db['objects']

        builtin_db['objects'] = {k: FW_OBJECT(*v) for k, v in builtin_db['objects'].items()}

        return builtin_db['version'], builtin_db

    def add(self, obj: config, /):
        '''["9003", "icmp", "built-in", "service", 1, "icmp/0", "<commonly> Ping"]
        '''
        user_objects = self.user_database['objects']

        obj_id = randint(*USER_RANGE)
        while obj_id in user_objects:
            obj_id = randint(*USER_RANGE)

        user_objects[obj_id] = FW_OBJECT(obj_id, *list(obj.values())[1:])

        self.user_database['ntoid'][obj.name] = obj_id

        self.db_changed = True

    def update(self, obj: config, /) -> None:
        try:
            self.user_database['objects'][obj.id] = FW_OBJECT(*obj.values())
        except KeyError:
            pass  # log this error with LogHandler or return error

        else:
            self.user_database['ntoid'][obj.name] = obj.id

            self.db_changed = True

    def remove(self, obj: config) -> None:

        # just checking for existence and to check the "group" field
        fw_object: FW_OBJECT = self.user_database['objects'].get(obj.id, MISSING_RULE)
        if (fw_object is MISSING_RULE):
            raise ValidationError(f'Firewall object {obj.id} not found.')  # LogHandler or return error

        # object group
        if (fw_object[2] != 'extended'):
            raise ValidationError('Only extended firewall objects can be removed.')

        self.user_database['ntoid'].pop(fw_object[1], None)

        # final removal of the object from the objects table
        del self.user_database['objects'][fw_object[0]]

        self.db_changed = True

    def lookup(self, oid: int, convert: bool = False) -> Union[int, list[int, int, int], FW_OBJECT]:
        '''return index of the object associated with sent in object id.

        if the id does not exist, None will be returned.
        '''
        if (not self.lookup_set):
            raise RuntimeError('The lookup flag must be set when initializing FWObjectManager to unlock this method.')

        fw_object: FW_OBJECT = self.full_db['objects'].get(oid, MISSING_RULE)
        if (not convert):
            return fw_object

        return INVALID_OBJECT if fw_object is MISSING_RULE else convert_object(fw_object)

    # ===========
    # VALIDATION
    # ===========
    # FIXME: see how this will work with different icons per each subtype
    def validate(self, icon: str, obj_name: str) -> Union[str, int]:
        '''return object id if valid, otherwise returns None
        '''
        # basic membership test and getting object reference
        object_id: int = self.full_db['ntoid'].get(obj_name, DATA.MISSING)
        if (object_id is DATA.MISSING):
            return INVALID_OBJECT

        # comparing the icon in the webui object to the db definition
        fw_object = FW_OBJECT(*self.full_db['objects'].get(object_id))
        if (fw_object.type != icon_map.get(icon)):
            return INVALID_OBJECT

        return object_id

    # None return is in list for compatibility with the normal process
    def iter_validate(self, fw_objs: str) -> list[int]:
        if (not self.lookup_set):
            raise RuntimeError('The lookup flag must be set when initializing FWObjectManager to unlock this method.')

        if (not fw_objs or 'none' in fw_objs):
            return [INVALID_OBJECT]

        # making a list of icon and obj_name pairs from raw string representation of data
        try:
            fw_objects: ITER_FW_OBJECTS = [x.split('/') for x in fw_objs.split(',')]
        except Exception:
            return [INVALID_OBJECT]

        results = []
        for obj in fw_objects:
            results.append(self.validate(*obj))

        return results

    # =================
    # DISK IO
    # =================
    def _load(self) -> dict:
        # user db wont exist until the first object is added
        if not os.path.isfile(USER_DB):
            return {
                'version': 1,
                'date': ['1', '1', '1'],
                'objects': {},
                'ntoid': {}
            }

        with open(USER_DB) as obj_db:
            string_db = obj_db.read()

            loaded_db = literal_eval(string_db.replace('\n', ''))

        loaded_db['objects'] = {k: FW_OBJECT(*v) for k, v in loaded_db['objects'].items()}

        return loaded_db

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
            DB_START, db_skey_val('date', System.date()), db_skey_val('version', db_version), table_start('objects')
        ]
        db_append = database.append

        # INDEX TABLE - NAME TO ID
        ntoid = [table_start('ntoid')]
        ntoid_append = ntoid.append

        # FORMATTING OBJECTS
        for obj in self.user_database['objects'].values():

            db_append(table_key_val(obj[0], obj))
            ntoid_append(table_skey_val(obj[1], obj[0]))

        # hack to strip the trailing comma on the last element in the list.
        database[-1] = database[-1][:-1]
        ntoid[-1] = ntoid[-1][:-1]

        db_append(TABLE_NEXT)

        database.extend(ntoid)

        db_append(TABLE_END)
        db_append(DB_END)

        return '\n'.join(database)
