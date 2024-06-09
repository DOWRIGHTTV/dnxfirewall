#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

def web_module_load_callout(filename: str) -> None:
    '''print passed in filename to stdout.

    only active when WEBUI_DEVELOPMENT is present in the environment.
    '''
    import os

    if os.environ.get('FLASK_ENV') == 'development':
        print(f'<| file import >> {filename} |>')


if (TYPE_CHECKING):
    from typing import TypeAlias, Type, Any, Callable, Optional, Union

    from threading import Lock as _Lock, Event as _Event

    Lock_T: TypeAlias = _Lock
    Event_T: TypeAlias = _Event

    from werkzeug.datastructures import ImmutableMultiDict, MultiDict

    Callable_T: TypeAlias = Callable[[Any, ...], Any]

    JSON: TypeAlias = dict[str, str]
    Form: TypeAlias = ImmutableMultiDict[str, str]
    Args: TypeAlias = MultiDict[str, str]

    WebLoadResponse: TypeAlias = dict[str, Any]

    STATUS: TypeAlias = bool
    ERROR_CODE: TypeAlias = int
    ERROR_MESSAGE: TypeAlias = str
    WebUpdateError: TypeAlias = tuple[ERROR_CODE, ERROR_MESSAGE]
    WebAjaxError: TypeAlias = dict[str, Union[int, str]]

    WebAjaxResponse: TypeAlias = [STATUS, WebAjaxError]

    from source.web_interfaces import StandardWebPage as _StandardWebPage
    from source.web_interfaces import LogWebPage as _LogWebPage
    from source.web_interfaces import RulesWebPage as _RulesWebPage

    StandardWebPage: TypeAlias = Type[_StandardWebPage]
    LogWebPage: TypeAlias = Type[_LogWebPage]
    RulesWebPage: TypeAlias = Type[_RulesWebPage]

    from dnx_gentools.def_typing import FirewallDBLock

    # todo: should this be here?
    from dnx_gentools.file_operations import ConfigChain
