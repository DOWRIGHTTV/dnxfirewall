#!/usr/bin/env python3

from __future__ import annotations

from functools import wraps

from dnx_gentools.def_constants import module_import_callout

module_import_callout(__file__)

from dnx_gentools.def_constants import TYPE_CHECKING
from dnx_gentools.def_enums import LOG as _LOG

# ================
# TYPING IMPORTS
# ================
if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Optional
    from dnx_routines.logging import LogHandler_T

class TerminateSignal(Exception):
    '''SigTerm will be sent by and received from systemd

    alternative to KeyboardInterrupt for when running as a service
    '''

class DNXError(Exception):
    '''Base error for all other DNX errors. '''

    @property
    def message(self) -> Optional[str]:
        return self.args[0]

class ControlError(DNXError):
    '''System Action (control) failure. This is reraised and a functional alias to other Exceptions.'''

class ProtocolError(DNXError):
    '''Malformed network protocol.'''

class ParseError(DNXError):
    '''Failure to convert string to python object.'''

def err_as_value(exc_type):
    '''converts try/catch semantic of the specified exception class to a return error by value.

    func(*args, **kwargs) -> Optional[ExceptionClass]

    manually returning exceptions as values is also supported.
    '''
    def decorator(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except exc_type as exc:
                return exc

        return wrapper

    return decorator


def dnx_assert(condition: bool, message: str, *, logger: LogHandler_T = None) -> None:
    '''DNX assertion function.

    If an assertion fails and a logger is provided, the message is logged prior to raising the exception.
    '''
    if (condition): return

    if (logger):
        logger.emergency(message)

    # todo: figure out how or what to do for the module name in the direct log.
    #  for now we will use "system" as catch all if no logger is provided.
    else:
        from dnx_routines.logging.log_client import direct_log

        direct_log('system', _LOG.EMERGENCY, message)

    raise AssertionError(message)
