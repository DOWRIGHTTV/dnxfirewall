#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING, Optional
from functools import wraps

# ================
# TYPING IMPORTS
# ================
if (TYPE_CHECKING):
    from dnx_routines.logging import LogHandler_T


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

    If an assertion fails and a logger is provided, the message is logger prior to raising the exception.
    '''
    if (condition): return

    if (logger):
        logger.emergency(message)

    raise AssertionError(message)
