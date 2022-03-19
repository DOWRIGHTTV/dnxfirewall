#!/usr/bin/env python3

from __future__ import annotations

# ====================
# DNXFIREWALL WEBUI
# ====================
from dnx_gentools.def_constants import INITIALIZE_MODULE

if INITIALIZE_MODULE('webui'):
    __all__ = ('app',)

    # app will be called by uwsgi
    from source.main.dfe_main import app

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    __all__ = ('ObjectManager',)

    from dnx_webui.source.main.dfe_obj_manager import _object_manager

    ObjectManager = _object_manager([])
