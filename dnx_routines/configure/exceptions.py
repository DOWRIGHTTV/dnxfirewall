#!/usr/bin/env python3

from typing import Optional


class DNXError(Exception):
    '''Base error for all other DNX errors. '''

    @property
    def message(self) -> Optional[str]:
        return self.args[0]

class ValidationError(DNXError):
    '''Error raised when front end validations fail to notify the user/front end there
    was a problem and provide a message of what happened. '''
