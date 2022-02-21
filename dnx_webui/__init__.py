#!/usr/bin/env python3

from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from dnx_webui.source.main.dfe_obj_manager import _object_manager

    ObjectManager = _object_manager([])

else:
    import os
    import sys

    # ====================
    # DNXFIREWALL WEB APP
    # ====================
    # app will be called by uwsgi
    HOME_DIR = os.environ.get('HOME_DIR', '/home/dnx/dnxfirewall')
    sys.path.insert(0, HOME_DIR)
    sys.path.insert(0, f'{HOME_DIR}/dnx_webui')

    from source.main.dfe_main import app
