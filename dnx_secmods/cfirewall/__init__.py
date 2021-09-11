import _os, _sys

_HOME_DIR = _os.environ.get('HOME_DIR', '/'.join(_os.path.realpath(__file__).split('/')[:-3]))
_sys.path.insert(0, _HOME_DIR)