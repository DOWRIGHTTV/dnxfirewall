#!/usr/bin/env python3

from __future__ import annotations

from typing import TYPE_CHECKING

if (TYPE_CHECKING):

    from cfirewall.fw_main import CFirewall

    from dns_proxy import *

    from ip_proxy import *

    from ips_ids import *
