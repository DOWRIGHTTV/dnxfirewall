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
    try:
        from source.main.dfe_main import app
    except ImportError as ie:
        print(f'webui import failure. {ie}. exiting...')
        os._exit(1)
