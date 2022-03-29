#!/usr/bin/env python3

from __future__ import annotations

import csv
import pprint

from copy import copy
from enum import IntEnum

from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import GEO, DATA
from dnx_gentools.def_namedtuples import FW_OBJECT

from dnx_iptools.cprotocol_tools import iptoi
from dnx_iptools.protocol_tools import cidr_to_int


__all__ = (
    'initialize', 'ADDR_OBJ', 'SVC_OBJ', 'INVALID_OBJECT', 'MISSING_RULE'
)

debug = pprint.PrettyPrinter(indent=4).pprint

_icon_to_type = {'border_inner': 'zone', 'tv': 'address', 'language': 'country', 'track_changes': 'service'}
INVALID_OBJECT = -1
MISSING_RULE = FW_OBJECT('none', 'none', 'none', 'none', 0, 'none', 'none')

class ADDR_OBJ(IntEnum):
    HOST = 1
    NETWORK = 2
    RANGE = 3
    GEO = 6

class SVC_OBJ(IntEnum):
    SOLO = 1
    RANGE = 2
    LIST = 3


def object_manager(object_list: list[FW_OBJECT]) -> ObjectManager:

    _object_version: int = 0
    _object_definitions: list[FW_OBJECT] = copy(object_list)

    # removing reference to the original object
    del object_list

    # {id: index}
    _id_to_idx: dict[int, int] = {x[0]: i for i, x in enumerate(_object_definitions)}
    _id_to_idx_get = _id_to_idx.get

    _name_to_idx: dict[str, int] = {x[1]: i for i, x in enumerate(_object_definitions)}
    _name_to_idx_get = _name_to_idx.get

    proto_convert: dict[str, int] = {'icmp': 1, 'tcp': 6, 'udp': 17}

    # TODO: this should be done one time/ precalculated
    def convert_object(obj: FW_OBJECT, /) -> Union[int, list[int], list[list]]:
        if (obj.type == 'address'):
            ip, netmask = obj.value.split('/')

            # type, int 32 bit ip, int 32 bit netmask
            return [ADDR_OBJ.HOST if netmask == '32' else ADDR_OBJ.NETWORK, iptoi(ip), cidr_to_int(netmask)]

        elif (obj.type == 'country'):

            # type, int 32 bit country code, null
            if (obj.subtype == ADDR_OBJ.GEO):
                return [ADDR_OBJ.GEO, GEO[obj.value.upper()].value, 0]

        elif (obj.type == 'service'):

            if (obj.subtype == SVC_OBJ.SOLO):
                proto, port = obj.value.split('/')

                return [SVC_OBJ.SOLO, proto_convert[proto], int(port), 0]

            elif (obj.subtype == SVC_OBJ.RANGE):
                proto, ports = obj.value.split('/')

                return [SVC_OBJ.RANGE, proto_convert[proto], *[int(p) for p in ports.split('-')]]

            elif (obj.subtype == SVC_OBJ.LIST):
                obj_list: list[Union[int, list]] = [SVC_OBJ.LIST]

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

    class _ObjectManager:

        __slots__ = ()

        @staticmethod
        def validate(icon: str, obj_name: str) -> Union[str, int]:
            '''return object id if valid, otherwise returns None
            '''
            idx = _name_to_idx_get(obj_name, DATA.MISSING)
            print(f'index found: {idx}')

            if (idx is DATA.MISSING):
                return INVALID_OBJECT

            input_type = _icon_to_type.get(icon, None)
            fw_obj_type = _object_definitions[idx].type
            print(f'obj type: {fw_obj_type}, input_field: {input_type}')

            if (input_type == fw_obj_type):
                return _object_definitions[idx].id

            else:
                return INVALID_OBJECT

        # None return is in list for compatibility with the normal process
        def iter_validate(self, fw_objects: str) -> list[int]:

            if (not fw_objects or 'none' in fw_objects):
                return [INVALID_OBJECT]

            # making a list of icon and obj_name pairs from raw string representation of data
            try:
                fw_objects: list[list[str, str]] = [x.split('/') for x in fw_objects.split(',')]
            except Exception:
                return [INVALID_OBJECT]

            results = []
            for obj in fw_objects:

                results.append(self.validate(*obj))

            return results

        @staticmethod
        def lookup(oid: int, convert: bool = False) -> Union[FW_OBJECT, int, list[int, int, int]]:
            '''return index of the object associated with sent in object id.

            if the id does not exist, None will be returned.
            '''
            idx = _id_to_idx_get(oid, DATA.MISSING)
            if (idx is DATA.MISSING):
                if (convert):
                    return INVALID_OBJECT

                return MISSING_RULE

            obj = _object_definitions[idx]

            if (convert):
                return convert_object(obj)

            return obj

        @staticmethod
        def get_objects() -> tuple[int, list[FW_OBJECT]]:
            '''returns the current version and full object list.
            '''
            return _object_version, _object_definitions

    if (TYPE_CHECKING):
        return _ObjectManager

    return _ObjectManager()


def initialize(home_dir: str) -> ObjectManager:
    object_list: list[list[str, str, str, str, Union[str, int], str, str]]
    obj: list

    with open(f'{home_dir}/dnx_webui/data/builtin_fw_objects.csv', 'r') as fw_objects:
        object_list = [x for x in csv.reader(fw_objects) if x and '#' not in x[0]][1:]

    formatted_object_list: list = []
    for obj in object_list:

        # replacing subtype with int to line up with cfirewall
        obj[4] = int(obj[4])

        formatted_object_list.append(FW_OBJECT(*obj))

    return object_manager(formatted_object_list)

