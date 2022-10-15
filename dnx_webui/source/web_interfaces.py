
from __future__ import annotations

from source.web_typing import *


class WebPage:
    '''super class for all other web page module types.'''
    @staticmethod
    def load(form: Form) -> dict[str, Any]:
        raise NotImplementedError('load page not defined.')

    @staticmethod
    def update(form: Form) -> tuple[int, str]:
        raise NotImplementedError('update page static not defined.')

    @staticmethod
    def handle_ajax(json_data: dict) -> tuple[bool, WebError]:
        raise NotImplementedError('handle ajax not defined.')


class StandardWebPage(WebPage):
    '''base class to be used with all standard web page module classes.

    its primary purpose to is to provide better static typing and error reporting/ handling.
    '''
    pass


class LogWebPage(WebPage):
    '''base class to be used with all log type web page module classes.

    its primary purpose to is to provide better static typing and error reporting/ handling.
    '''
    @staticmethod
    def update(form: Form) -> tuple[str, Optional[str], list]:
        raise NotImplementedError('update page not defined.')


class RulesWebPage(WebPage):
    '''base class to be used with all rules web page module classes.

    its primary purpose to is to provide better static typing and error reporting/ handling.
    '''
    @staticmethod
    def load(section: str) -> dict[str, Any]:
        raise NotImplementedError('load page not defined.')

    @staticmethod
    def update(form: Form) -> tuple[str, str]:
        raise NotImplementedError('update page static not defined.')