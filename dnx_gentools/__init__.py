#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

if (TYPE_CHECKING):

    from def_namedtuples import L_SOCK as LI_SOCK

    ByteContainer = bytecontainer('ByteContainer', 'field_a field_b field_n')
