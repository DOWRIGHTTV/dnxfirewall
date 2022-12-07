#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from typing import TypeAlias, Type, Any, Callable, ByteString, Optional, Union

    from threading import Lock, Event

    from werkzeug.datastructures import ImmutableMultiDict, MultiDict

    Callable_T: TypeAlias = Callable[[Any, ...], Any]

    Form = ImmutableMultiDict[str, str]
    Args = MultiDict[str, str]
    WebError = dict[str, Union[int, str]]

    from source.web_interfaces import StandardWebPage as _StandardWebPage
    from source.web_interfaces import LogWebPage as _LogWebPage
    from source.web_interfaces import RulesWebPage as _RulesWebPage

    StandardWebPage: TypeAlias = Type[_StandardWebPage]
    LogWebPage: TypeAlias = Type[_LogWebPage]
    RulesWebPage: TypeAlias = Type[_RulesWebPage]

    from dnx_gentools.file_operations import ConfigChain
