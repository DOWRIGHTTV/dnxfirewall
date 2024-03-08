#!/usr/bin/python3

from __future__ import annotations

import re

from flask import session

from source.web_typing import *
from source.web_validate import *

from dnx_iptools.interface_ops import InterfaceManager
from dnx_iptools.protocol_tools import get_routing_table

from source.web_interfaces import StandardWebPage

__all__ = ('WebPage',)


class WebPage(StandardWebPage):
    '''
    available methods: load, update
    '''
    @staticmethod
    def load(form: Form) -> dict[str, Any]:
        return {'routing_table': get_routing_table()}

    @staticmethod
    def update(form: Form) -> tuple[int, str]:
        return NO_STANDARD_ERROR

# ==============
# VALIDATION
# ==============

# ==============
# CONFIGURATION
# ==============
