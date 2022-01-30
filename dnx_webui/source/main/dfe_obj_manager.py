#!/usr/bin/env python3

import csv

from copy import copy
from collections import namedtuple
import pprint
#
debug = pprint.PrettyPrinter(indent=4).pprint

_FW_OBJECT = namedtuple('fw_object', 'id name origin type value description')

_icon_to_type = {'tv': 'address', 'language': 'country', 'track_changes': 'service'}

def _object_manager(object_list):

    _object_version = 0
    _object_definitions = copy(object_list)

    # removing reference to original object
    del object_list

    # {id: index}
    _id_to_idx = {x[0]: i for i, x in enumerate(_object_definitions)}
    _id_to_idx_get = _id_to_idx.get

    _name_to_idx = {x[1]: i for i, x in enumerate(_object_definitions)}
    _name_to_idx_get = _name_to_idx.get

    # debug(_id_to_idx)

    class ObjectManager:

        __slots__ = ()

        @staticmethod
        def validate(icon, obj_name):
            '''returns object id if valid, otherwise returns None'''

            idx = _name_to_idx_get(obj_name, None)
            print(f'index found: {idx}')

            if (not idx):
                return None

            input_type = _icon_to_type.get(icon, None)
            fw_obj_type = _object_definitions[idx].type
            print(f'obj type: {fw_obj_type}, input_field: {input_type}')

            if (input_type == fw_obj_type):
                return _object_definitions[idx].id

            else:
                return None

        # None return is in list for compatibility with normal process
        def iter_validate(self, fw_objects):

            fw_objects = fw_objects.split()
            if (not fw_objects):
                return [None]

            # making list of icon, obj_name pairs from raw string representation of data
            try:
                fw_objects = [fw_objects[i:i + 2] for i in range(0, len(fw_objects), 2)]
            except Exception:  # TODO: consider making this more specific. probably not though lol.
                return [None]

            print('after reformat', fw_objects)

            results = []
            for obj in fw_objects:

                print(obj)
                results.append(self.validate(*obj))

            return results

        @staticmethod
        def lookup(id):
            '''return index of object associated with sent in object id. if id does not exist, None will be returned.'''

            idx = _id_to_idx_get(id, None)

            print(f'[lookup] id={id}, idx={idx}')

            return _object_definitions[idx] if idx else None

        @staticmethod
        def get_objects():
            '''returns current version and full object list. a version comparison can be done to rectify changes
               if needed'''

            return _object_version, _object_definitions

    return ObjectManager()


def initialize(HOME_DIR):
    with open(f'{HOME_DIR}/dnx_webui/data/builtin_fw_objects.csv', 'r') as fw_objects:
        object_list = [x for x in csv.reader(fw_objects) if x and '#' not in x[0]][1:]

    formatted_object_list = []
    for obj in object_list:

        formatted_object_list.append(_FW_OBJECT(*obj))

    return _object_manager(formatted_object_list)

