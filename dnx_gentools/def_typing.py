#!/usr/bin/env python3

from typing import TYPE_CHECKING, Type, Callable, Union, Optional, Dict, List, Tuple, NamedTuple

# NOTE: splitting if statements as import organization
# standard lib imports
if (TYPE_CHECKING):
    from ipaddress import IPv4Address

# dnx class imports for use as Types
if (TYPE_CHECKING):
    # gentools
    from def_enums import *
    from def_namedtuples import *

    # module packs
    from dnx_routines import *
    from dnx_secmods import *
    from dnx_netmods import *

ProxyCallback = Callable[..., None]
