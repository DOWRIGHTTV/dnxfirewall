#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from fw_main import CFirewall, nl_open, nl_bind, nl_break, initialize_geolocation

from fw_main.fw_main import CFirewall, nl_open, nl_bind, nl_break, initialize_geolocation
