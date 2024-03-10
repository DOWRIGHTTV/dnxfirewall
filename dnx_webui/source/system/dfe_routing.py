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

ROUTE_CODES = [
    'C - connected',
    'S - static',
    'NA - not available'
]
route_codes = ', '.join(ROUTE_CODES)

ROUTE_MODIFIERS = [
    '(D) - default route',
    '(H) - host route',
    '(I) - inactive (not implemented)'
]
route_modifiers = ', '.join(ROUTE_MODIFIERS)


class WebPage(StandardWebPage):
    '''
    available methods: load, update
    '''
    @staticmethod
    def load(form: Form) -> dict[str, Any]:
        route_table = set(get_routing_table())

        with InterfaceManager() as intf_mgr:
            configured_routes = set(intf_mgr.get_configured_routes())

        not_available = configured_routes - route_table

        for route in not_available:
            route.status = 0

        return {
            'route_codes': route_codes,
            'route_modifiers': route_modifiers,
            'routing_table': list(route_table & not_available)
        }

    @staticmethod
    def update(form: Form) -> tuple[int, str]:
        return NO_STANDARD_ERROR

# ==============
# VALIDATION
# ==============

# ==============
# CONFIGURATION
# ==============
