#!/usr/bin/env python3

from typing import TYPE_CHECKING, Callable, Union, Optional, Dict, List, Tuple, NamedTuple

# dnx class imports for use as Types
if (TYPE_CHECKING):
    # gentools
    from dnx_enums import *

    # module packs
    from dnx_routines import *

ProxyCallback = Callable[..., None]
