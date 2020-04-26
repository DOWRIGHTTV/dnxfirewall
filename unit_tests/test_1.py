#!/usr/bin/env python3

def test_one(data):
    assert(isinstance(data, bytes))
    assert(0 < len(data) < 65535)
