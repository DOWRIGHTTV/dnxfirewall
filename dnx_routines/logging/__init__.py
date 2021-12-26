import os as _os
import sys as _sys

HOME_DIR = _os.environ.get('HOME_DIR', '/'.join(_os.path.realpath(__file__).split('/')[:-3]))
_sys.path.insert(0, HOME_DIR)
