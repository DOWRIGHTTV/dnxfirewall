#!/usr/bin/env python3

from typing import Optional, Union, Any

from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from dnx_gentools.file_operations import ConfigChain

    from werkzeug.datastructures import ImmutableMultiDict

    Form = ImmutableMultiDict[str, str]
