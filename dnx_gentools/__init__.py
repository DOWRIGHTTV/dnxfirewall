#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

if (TYPE_CHECKING):

    from def_namedtuples import L_SOCK as LI_SOCK

    from standard_tools import structure as _structure, bytecontainer as _bytecontainer

    Structure = _structure('Structure', '')
    ByteContainer = _bytecontainer('ByteContainer', '')
