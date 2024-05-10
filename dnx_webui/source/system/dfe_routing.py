#!/usr/bin/python3

from __future__ import annotations

from source.web_typing import *

web_module_load_callout(__file__)

from source.web_validate import *

from dnx_gentools.def_constants import ONE_SEC, fast_sleep
from dnx_gentools.def_exceptions import err_as_value
from dnx_gentools.file_operations import ConfigurationError, config
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
    def load(form: Form) -> WebLoadResponse:

        return {
            'route_codes': route_codes,
            'route_modifiers': route_modifiers,
            'routing_table': get_unified_routes()
        }

    @staticmethod
    def update(form: Form) -> WebUpdateError:

        error, route_info = form_validator.parse_form(form)
        if (error):
            return 1, error.message

        if (route_info.btn == 'route_add'):

            if error := configure_route_add(route_info):
                return 11, error.message

        elif (route_info.btn == 'route_del'):

            if error := configure_route_del(route_info):
                return 21, error.message

        # note: this is probably not needed anymore
        else:
            return 99, INVALID_FORM

        # todo: delay is to allow for the routing table to be updated before the page is loaded.
        #    this is a temporary fix and should be replaced (probably by adding response/wait to control socket).
        fast_sleep(ONE_SEC)

        return NO_STANDARD_ERROR


# ==============
# VALIDATION
# ==============
def validate_adm_distance(adm_distance: str) -> Optional[ValidationError]:
    if (adm_distance not in ['10', '20', '60', '100']):
        return ValidationError('Invalid administrative distance.')

err_as_value(ValidationError)
def validate_route_del(route: str) -> Optional[ValidationError]:
    try:
        intf, net_id, net_mask, gateway, adm_distance = route.split(', ')
    except ValueError:
        return ValidationError(INVALID_FORM)

    if (adm_distance not in ['10', '20', '60', '100']):
        return ValidationError(INVALID_FORM)

    ip_address(ip_iter=[net_id, gateway])
    cidr(net_mask)

# =========================
# FORM VALIDATION TEMPLATE
# =========================
form_validator = ValidationConfigForm({
    'route_add': {
        # 'on_enter': ValidationFieldContext(),
        'nid': ValidationFieldInfo(cfg_key='net_id', format=ip_address),
        'nmk': ValidationFieldInfo(cfg_key='net_mask', format=ip_address),
        'nxh': ValidationFieldInfo(cfg_key='gateway', format=ip_address),
        'nad': ValidationFieldInfo(cfg_key='adm_distance', format=check_digit, validation=validate_adm_distance),
        'on_exit': ValidationFieldContext(call=lambda cfg: ip_network(f'{cfg.net_id}/{cfg.net_mask}'))
    },
    'route_del': {
        # 'on_enter': ValidationFieldContext(call=lambda form: ValidationError('Unable to remove routes at this time.')),
        'route_del': ValidationFieldInfo(cfg_key='route_str', validation=validate_route_del),
        'on_exit': ValidationFieldContext(call=lambda cfg: cfg.update({'route_obj': Route(*cfg.route_str.split(', '))}))
    }
})
# ==============
# CONFIGURATION
# ==============
def configure_route_add(route: config) -> Optional[ConfigurationError]:
    next_hop_route = route_lookup(route.gateway)
    if next_hop_route is None:
        return ConfigurationError('Unable to determine exit interface for the next hop IP Address.')

    new_route = Route(
        next_hop_route.intf, route.net_id, str(masktocidr(route.net_mask)), route.gateway, route.adm_distance
    )

    interface_manager = InterfaceManager()
    with interface_manager:
        interface_manager.add_route(new_route)

    return interface_manager.error

def configure_route_del(route: config) -> Optional[ConfigurationError]:
    interface_manager = InterfaceManager()
    with interface_manager:
        interface_manager.del_route(route.route_obj)

    return interface_manager.error
