#!/usr/bin/env python3

from __future__ import annotations

# ==================
# DNXFIREWALL WEBUI
# ==================
if (__name__ == '__main__'):
    __all__ = ('app',)

    import os
    import sys

    HOME_DIR = os.environ['HOME_DIR']
    WEB_DIR  = os.environ['WEB_DIR']

    sys.path.insert(0, HOME_DIR)
    sys.path.insert(0, WEB_DIR)

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
