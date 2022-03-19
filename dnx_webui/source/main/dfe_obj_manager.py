#!/usr/bin/env python3

from __future__ import annotations

import csv
import pprint

from copy import copy
from collections import namedtuple

from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import GEO, DATA

from dnx_iptools.cprotocol_tools import iptoi
from dnx_iptools.protocol_tools import cidr_to_int

debug = pprint.PrettyPrinter(indent=4).pprint

_FW_OBJECT = namedtuple('fw_object', 'id name origin type value description')
_icon_to_type = {'tv': 'address', 'language': 'country', 'track_changes': 'service'}
INVALID_OBJECT = -1


def _object_manager(object_list: list[_FW_OBJECT]) -> ObjectManager:

    _object_version: int = 0
    _object_definitions: list[_FW_OBJECT] = copy(object_list)

    # removing reference to the original object
    del object_list

    # {id: index}
    _id_to_idx: dict[int, int] = {x[0]: i for i, x in enumerate(_object_definitions)}
    _id_to_idx_get = _id_to_idx.get

    _name_to_idx: dict[str, int] = {x[1]: i for i, x in enumerate(_object_definitions)}
    _name_to_idx_get = _name_to_idx.get

    proto_convert: dict[str, int] = {'icmp': 1, 'tcp': 6, 'udp': 17}

    def convert_object(obj: _FW_OBJECT, /) -> list[int, int, int]:
        if (obj.type == 'address'):
            ip, netmask = obj.value.split('/')

            # type, int 32 bit ip, int 32 bit netmask
            return [1 if netmask == '32' else 2, iptoi(ip), cidr_to_int(netmask)]

        # type, int 32 bit country code, null
        elif (obj.type == 'country'):
            return [3, GEO[obj.value.upper()].value, 0]

        elif (obj.type == 'service'):

            proto, port = obj.value.split('/')

            ports = [int(p) for p in port.split('-')]
            if (len(ports) == 1):

                # a single port will be defined as a range starting and ending with itself.
                return [proto_convert[proto], ports[0], ports[0]]

            else:
                return [proto_convert[proto], ports[0], ports[1]]

        # not implemented at this time
        elif (obj.type == 'zone'):
            pass

        return [0, 0]

    class ObjectManager:

        __slots__ = ()

        @staticmethod
        def validate(icon: str, obj_name: str) -> int:
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
        def lookup(oid: int, convert: bool = False) -> Union[Optional[_FW_OBJECT], list[int, int, [Optional[int]]]]:
            '''return index of the object associated with sent in object id.

            if the id does not exist, None will be returned.
            '''
            idx = _id_to_idx_get(oid, DATA.MISSING)
            if (idx is DATA.MISSING):
                return None

            obj = _object_definitions[idx]

            if (convert):
                return convert_object(obj)

            return obj

        @staticmethod
        def get_objects() -> tuple[int, list[_FW_OBJECT]]:
            '''returns the current version and full object list.
            '''
            return _object_version, _object_definitions

    return ObjectManager()


def initialize(home_dir: str) -> ObjectManager:
    with open(f'{home_dir}/dnx_webui/data/builtin_fw_objects.csv', 'r') as fw_objects:
        object_list = [x for x in csv.reader(fw_objects) if x and '#' not in x[0]][1:]

    formatted_object_list: list = []
    for obj in object_list:

        formatted_object_list.append(_FW_OBJECT(*obj))

    return _object_manager(formatted_object_list)

