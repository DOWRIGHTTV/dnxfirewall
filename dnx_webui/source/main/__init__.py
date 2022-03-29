#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

if (TYPE_CHECKING):

    from dnx_gentools.def_namedtuples import FW_OBJECT as _FW_OBJECT

    from dfe_obj_manager import object_manager as _object_manager

    fw_object = _FW_OBJECT('id', 'name', 'origin', 'type', 0, 'value', 'description')

    ObjectManager = _object_manager([fw_object])
