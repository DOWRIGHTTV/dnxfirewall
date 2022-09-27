#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from types import ModuleType
    from typing import Protocol, TypeAlias, Any, Callable, ByteString, Optional, Union

    from threading import Lock, Event

    from werkzeug.datastructures import ImmutableMultiDict, MultiDict

    Callable_T: TypeAlias = Callable[[Any, ...], Any]

    Form = ImmutableMultiDict[str, str]
    Args = MultiDict[str, str]
    WebError = dict[str, Union[int, str]]

    # WTF is this shit.

    class StandardWebPage(Protocol):
        def load_page(self, _: Union[Form, Args]) -> dict[str, Any]: ...
        def update_page(self, _: Form) -> tuple[int, str]: ...

    from dnx_gentools.file_operations import ConfigChain, config
