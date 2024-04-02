#!/usr/bin/python3

from __future__ import annotations

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_enums import DATA
from dnx_gentools.file_operations import ConfigurationError, config, system_configuration
from dnx_iptools.interface_ops import InterfaceManager, get_unified_routes, route_lookup
from dnx_iptools.protocol_tools import Route, masktocidr

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

        return {
            'route_codes': route_codes,
            'route_modifiers': route_modifiers,
            'routing_table': get_unified_routes()
        }

    @staticmethod
    def update(form: Form) -> tuple[int, str]:
        if ('route_add' in form):
            route_info = config(**{
                'net_id': form.get('nid', DATA.MISSING),
                'net_mask': form.get('nmk', DATA.MISSING),
                'gateway': form.get('nxh', DATA.MISSING),
                'adm_distance': get_convert_int(form, 'nad')
            })

            if error := validate_route_add(route_info):
                return 1, error.message

            if error := configure_route(route_info):
                return 2, error.message

        elif ('route_del' in form):
            return 3, 'unable to delete route at this time.'

        else:
            return 99, INVALID_FORM

        return NO_STANDARD_ERROR

# ==============
# VALIDATION
# ==============
@input_validation
def validate_route_add(route: config) -> Optional[ValidationError]:
    if (route.adm_distance not in [10, 20, 60, 100]):
        return ValidationError(INVALID_FORM)

    ip_address(ip_iter=[route.net_id, route.net_mask, route.gateway])

# ==============
# CONFIGURATION
# ==============
@system_configuration
def configure_route(route: config) -> Optional[ConfigurationError]:
    next_hop_route = route_lookup(route.gateway)
    if next_hop_route is None:
        return ConfigurationError('Unable to determine exit interface for the next hop IP Address.')

    new_route = Route(
        next_hop_route.intf, route.net_id, str(masktocidr(route.net_mask)), route.gateway, route.adm_distance
    )

    with InterfaceManager() as intf_mgr:
        intf_mgr.add_route(new_route)
