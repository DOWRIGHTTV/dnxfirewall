#!/usr/bin/env python3

# LABEL: DEVELOPMENT_ONLY_CODE

from __future__ import annotations


def test_one(data):
    assert(isinstance(data, bytes))
    assert(0 < len(data) < 65535)