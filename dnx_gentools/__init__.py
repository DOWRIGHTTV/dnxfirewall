#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from standard_tools import *
    from file_operations import *

    ByteContainer = bytecontainer('ByteContainer', 'field_a field_b field_n')
