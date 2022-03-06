#!/usr/bin/env python3

from __future__ import annotations

from typing import Optional


class DNXError(Exception):
    '''Base error for all other DNX errors. '''

    @property
    def message(self) -> Optional[str]:
        return self.args[0]

class ValidationError(DNXError):
    '''Raised on webui processing failures.'''
