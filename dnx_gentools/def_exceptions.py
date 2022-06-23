#!/usr/bin/env python3

from __future__ import annotations

from typing import Optional


class DNXError(Exception):
    '''Base error for all other DNX errors. '''

    @property
    def message(self) -> Optional[str]:
        return self.args[0]

class ValidationError(DNXError):
    '''Webui processing failure or invalid user input.'''

class ConfigurationError(DNXError):
    '''ConfigurationManager processing failure while in context.'''

class ControlError(DNXError):
    '''System Action (control) failure. This is reraised and a functional alias to other Exceptions.'''

class ProtocolError(DNXError):
    '''Malformed network protocol.'''
