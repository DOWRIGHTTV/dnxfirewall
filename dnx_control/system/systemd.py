from __future__ import annotations

import os
import signal
import socket

from dnx_gentools.def_exceptions import TerminateSignal, dnx_assert
from dnx_gentools.def_constants import console_log

__all__ = (
    'sysd_notify_ready', 'sysd_notify_stopping'
)

# ====================
# NOTIFY SOCKET
# ====================
NOTIFY_SOCKET = os.environ.get('NOTIFY_SOCKET', '')
if (NOTIFY_SOCKET):
    dnx_assert(NOTIFY_SOCKET[0] in ("/", "@"), "Notify socket type not supported.")

    # abstract socket
    if NOTIFY_SOCKET[0] == "@":
        NOTIFY_SOCKET = "\0" + NOTIFY_SOCKET[1:]

# ====================
# NOTIFY SENDER
# ====================
if (not NOTIFY_SOCKET):
    def _notify(message: bytes) -> None:
        console_log(f"NOTIFY_SOCKET not set, skipping notification: {message}")

else:
    def _notify(message: bytes) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as sock:
            sock.connect(NOTIFY_SOCKET)
            sock.sendall(message)

# ====================
# NOTIFY HELPERS
# ====================
def sysd_notify_ready() -> None:
    _notify(b"READY=1")

def sysd_notify_stopping() -> None:
    _notify(b"STOPPING=1")

# ====================
# SIGNAL HANDLERS
# ====================
def _terminate_handler(signum, frame):
    raise TerminateSignal('SIGTERM')

signal.signal(signal.SIGTERM, _terminate_handler)
