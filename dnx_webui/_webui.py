#!/usr/bin/env python3

from __future__ import annotations

import os
import sys

HOME_DIR = os.environ.get('HOME_DIR', '/home/dnx/dnxfirewall')
sys.path.insert(0, HOME_DIR)
sys.path.insert(0, f'{HOME_DIR}/dnx_webui')

import source.main.dfe_main