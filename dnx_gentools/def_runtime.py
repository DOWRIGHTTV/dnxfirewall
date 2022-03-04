#!/usr/bin/env python3

from __future__ import annotations

import os as _os
import sys as _sys

HOME_DIR: str = _os.environ.get('HOME_DIR', '/'.join(_os.path.realpath(__file__).split('/')[:-2]))

_sys.path.insert(0, HOME_DIR)
