
from __future__ import annotations

from typing import TypedDict

from source.web_typing import web_module_import_callout

web_module_import_callout(__file__)

from dnx_gentools.def_constants import TYPE_CHECKING

if (TYPE_CHECKING):
    from source.web_typing import Optional, Union

    from source.web_typing import Form, Args, JSON, WebLoadResponse, WebUpdateError, WebAjaxResponse

# Response Types
class WebAjaxContent(TypedDict):
    '''ajax response content.

    error: int
    message: str
    data: Union[list, dict]
    '''
    error: int
    message: str
    data: Union[list, dict]


# Web Page Types
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
    def load(form: Form, error: bool = False, uri_query: Optional[Args] = None) -> WebLoadResponse:
        raise NotImplementedError('update page not defined.')

    # @staticmethod
    # def update(form: Form) -> WebUpdateError:
    #     raise NotImplementedError('update page not defined.')

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