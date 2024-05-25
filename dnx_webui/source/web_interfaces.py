
from __future__ import annotations

from source.web_typing import *

web_module_load_callout(__file__)


class WebPage:
    '''superclass for all other web page module types.'''
    @staticmethod
    def load(form: Form) -> WebLoadResponse:
        raise NotImplementedError('load page not defined.')

    @staticmethod
    def update(form: Form) -> WebUpdateError:
        raise NotImplementedError('update page not defined.')

    @staticmethod
    def handle_ajax(aform: JSON) -> WebAjaxResponse:
        raise NotImplementedError('handle ajax not defined.')


class StandardWebPage(WebPage):
    '''base class to be used with all standard web page module classes.

    its primary purpose is to provide better static typing and error reporting/ handling.
    '''
    pass


class LogWebPage(WebPage):
    '''base class to be used with all log type web page module classes.

    its primary purpose is to provide better static typing and error reporting/ handling.
    '''
    @staticmethod
    def update(form: Form) -> tuple[str, Optional[str], list]:
        raise NotImplementedError('update page not defined.')


class RulesWebPage(WebPage):
    '''base class to be used with all rules web page module classes.

    its primary purpose is to provide better static typing and error reporting/ handling.
    '''
    @staticmethod
    def load(section: str) -> WebLoadResponse:
        raise NotImplementedError('load page not defined.')

    @staticmethod
    def update(form: Form) -> tuple[str, str]:
        raise NotImplementedError('update page static not defined.')