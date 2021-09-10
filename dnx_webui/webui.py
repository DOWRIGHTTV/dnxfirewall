#!/usr/bin/env python3

import os, sys

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-3]))
sys.path.insert(0, HOME_DIR)

from dnx_webui.dfe_dnx_main import app as application

if __name__ == '__main__':
    application.run()
