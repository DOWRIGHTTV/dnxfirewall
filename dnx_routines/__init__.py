#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING


# FIXME: WHAT THE FUCK IS WRONG WITH THIS PIECE OF SHIT.
if (TYPE_CHECKING):
    # from logging import *
    from dnx_routines.logging import *

    from database import *
