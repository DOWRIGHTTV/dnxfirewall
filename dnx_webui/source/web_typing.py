#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING
from collections import defaultdict as _dd

def web_module_load_callout(filename: str, import_cache: _dd[str, int] = _dd(int)) -> None:
    '''print passed in filename to stdout.

    only active when FLASK_ENV=development
    '''
    import os

    # note: only need the counter if circular imports will actually run through a file twice.
    _dd[filename] += 1
    if os.environ.get('FLASK_ENV') == 'development':
        print(f'importing <<{filename}[{_dd[filename]}]>>')

if (TYPE_CHECKING):
    from typing import TypeAlias, Type, Any, Callable, ByteString, Optional, Union

    from threading import Lock as _Lock, Event as _Event

    Lock_T: TypeAlias = _Lock
    Event_T: TypeAlias = _Event

    from werkzeug.datastructures import ImmutableMultiDict, MultiDict

    Callable_T: TypeAlias = Callable[[Any, ...], Any]

    JSON: TypeAlias = dict[str, Any]
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

    from dnx_gentools.file_operations import ConfigChain
