#!/usr/bin/env python3

import os
import sys

from dnx_webui.source.main.dfe_main import app as application

if (__name__ == '__main__'):
    sys.path.insert(
        0, os.environ.get('HOME_DIR', '/home/dnx/dnxfirewall')
    )

    application.run()
