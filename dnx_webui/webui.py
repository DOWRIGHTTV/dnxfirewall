#!/usr/bin/env python3

import os, sys

HOME_DIR = os.environ.get('HOME_DIR', os.path.dirname(os.path.dirname((os.path.realpath('__file__')))))
sys.path.insert(0, HOME_DIR)

from dnx_webui.dfe_dnx_main import app as application

if __name__ == '__main__':
    application.run()
