#!/usr/bin/env python3

from __future__ import annotations

import os
import sys

# ==================
# DNXFIREWALL WEBUI
# ==================
INITIALIZE_MODULE = os.environ.get('INIT', False)

if (INITIALIZE_MODULE):
    __all__ = ('app',)

    HOME_DIR = os.environ['HOME_DIR']
    WEB_DIR  = os.environ['WEB_DIR']

    sys.path.insert(0, HOME_DIR)
    sys.path.insert(0, WEB_DIR)

    # app will be called by uwsgi
    from source.main.dfe_main import app

# ===============
# TYPING
# ===============
from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    __all__ = ('ObjectManager',)

    from dnx_gentools.def_namedtuples import FW_OBJECT
    from dnx_webui.source.main.dfe_obj_manager import object_manager

    fw_object = FW_OBJECT('id', 'name', 'origin', 'type', 0, 'value', 'description')

    ObjectManager = object_manager([fw_object])
