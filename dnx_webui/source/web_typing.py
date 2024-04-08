#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from typing import TypeAlias, Type, Any, Callable, ByteString, Optional, Union, Lamb

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
