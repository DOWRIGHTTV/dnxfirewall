#!/usr/bin/python3

from __future__ import annotations

import json
import string

from typing import NamedTuple as _NamedTuple
from collections import defaultdict

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.def_enums import DATA
from dnx_gentools.file_operations import load_configuration, config

from dnx_secmods.cfirewall.fw_control import FirewallControl

from source.web_typing import *
from source.web_validate import ValidationError, standard, full_field, proto_port, ip_network, ip_address
from source.web_validate import get_convert_int, convert_int
from source.object_manager import FWObjectManager, USER_RANGE

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_namedtuples import FW_OBJECT

valid_sections: dict[str, str] = {'BEFORE': '1', 'MAIN': '2', 'AFTER': '3'}

reference_counts = defaultdict(int)
zone_map: dict[str, dict] = {'builtins': {}, 'extended': {}}
zone_manager: dict[str, dict] = {'builtins': {}, 'user-defined': {}}

INVALID_OBJECT = -1

INTRA_ZONE = 0
ANY_ZONE = 99

_properties = {
    ('address', 1): ['light-blue lighten-2', 'tv'], ('address', 2): ['blue lighten-2', 'track_changes'],
    ('address', 3): ['indigo lighten-2', 'track_changes'], ('address', 6): ['red lighten-2', 'vpn_lock'],
    ('service', 1): ['light-green lighten-2', 'dns'], ('service', 2): ['green lighten-2', 'dns'],
    ('service', 3): ['lime lighten-2', 'dns'],
    ('zone', 1): ['deep-purple lighten-2', 'border_inner'], ('zone', 2): ['purple lighten-2', 'border_inner']
}
def format_fw_obj(fw_obj: list, /) -> list[str, str]:
    properties = _properties.get((fw_obj[3], fw_obj[4]), ['', ''])

    return [
        (f'<div class="chip tooltipped {properties[0]}" data-html="true" data-tooltip="<p style=width:160px>'
            f'{fw_obj[2]}<br>{fw_obj[3]}<br>{fw_obj[5]}<br>{fw_obj[6]}</p>">'
            f'<i class="material-icons tiny {properties[0]} valign-center">{properties[1]}</i> {fw_obj[1]}</div>'),
        f'<i class="material-icons tiny valign-center">{properties[1]}</i>', properties[0]]


return_data: tuple[bool, dict[str, Union[bool, str]]]

def load_page(section: str) -> dict[str, Any]:
    lzone_map: dict[int, str] = {ANY_ZONE: 'any'}

    dnx_settings: ConfigChain = load_configuration('system')

    # building out interface to zone map NOTE: builtins only for now
    for intf_type in ['builtins', 'extended']:
        for intf_name, intf_info in dnx_settings.get_items(f'interfaces->{intf_type}'):
            ident = intf_info['ident']

            zone_map[intf_type][ident] = intf_name

            # need to make converting zone ident/int to name easier in format function
            zone_ident = dnx_settings[f'zones->builtins->{intf_name}'][0]

            # TODO: is lzone_map needed after moving zones to fw objects?
            lzone_map[zone_ident] = intf_name

    reference_counts.clear()
    # NOTE: this needs to be before the zone manager builds, so we can get reference counts
    firewall_rules = get_and_format_rules(section)

    # TODO: this is now unoptimized.
    #  we should track ref counts in in FirewallControl class and inc/dec when rule is deleted or added.
    # calculate_ref_counts(firewall_rules)

    # building zone list and reference counts NOTE: builtins only for now
    for zone_type in ['builtins', 'user-defined']:
        for zone_name, (zone_ident, zone_desc) in dnx_settings.get_items(f'zones->{zone_type}'):

            zone_manager[zone_type][zone_name] = [reference_counts[zone_name], zone_desc]

    version: int
    firewall_objects: dict[str, list]
    version, firewall_objects = FWObjectManager.get_objects()

    # fw_object_map: dict[str, dict] = {obj.name: {'type': obj.type, 'id': obj.id} for obj in firewall_objects}
    fw_object_map = {o[1]: format_fw_obj(o) for o in firewall_objects.values()}

    # FIXME: this is redundant, but needed to rendering the firewall object list.
    #  this should only be used for jinja at least it shouldnt be getting sent to client.
    firewall_objects = {o[1]: o for o in firewall_objects.values()}

    zone_autofill: dict[str, None] = {k: None for k, v in firewall_objects.items() if v[3] in ['zone']}
    network_autofill: dict[str, None] = {k: None for k, v in firewall_objects.items() if v[3] in ['address']}
    service_autofill: dict[str, None] = {k: None for k, v in firewall_objects.items() if v[3] in ['service']}

    return {
        'zone_map': zone_map,
        'zone_manager': zone_manager,
        'firewall_objects': firewall_objects,
        'fw_object_map': fw_object_map,
        'zone_autofill': zone_autofill,
        'network_autofill': network_autofill,
        'service_autofill': service_autofill,
        'firewall_rules': firewall_rules,
        'pending_changes': FirewallControl.is_pending_changes()
    }

def update_page(form: Form) -> tuple[str, str]:

    # initial input validation for presence of zone field
    section: str = form.get('section', 'MAIN')

    if ('create_obj' in form):
        fw_object = config(**{
            'id': 0,
            'name': form.get('ocname', DATA.MISSING),
            'group': 'extended',  # hardcoded
            'type': form.get('octype', DATA.MISSING),
            'subtype': 0,  # temp value replaced in validation
            'value': form.get('ocvalue', DATA.MISSING),
            'desc': form.get('ocdesc', DATA.MISSING)
        })

        if (DATA.MISSING in fw_object.values()):
            return INVALID_FORM, section

        error = validate_object(fw_object)
        if (error):
            return error.message, section

        try:
            with FWObjectManager() as obj_manager:
                obj_manager.add(fw_object)
        except ValidationError as ve:
            return ve.message, section

    elif('edit_obj' in form):
        fw_object = config(**{
            'id': get_convert_int(form, 'oeid'),
            'name': form.get('oename', DATA.MISSING),
            'group': 'extended',  # hardcoded
            'type': form.get('oetype', DATA.MISSING),
            'subtype': 0,  # temp value replaced in validation
            'value': form.get('oevalue', DATA.MISSING),
            'desc': form.get('oedesc', DATA.MISSING)
        })

        if (DATA.MISSING in fw_object.values()):
            return INVALID_FORM, section

        error = validate_object(fw_object)
        if (error):
            return error.message, section

        try:
            with FWObjectManager() as obj_manager:
                obj_manager.update(fw_object)
        except ValidationError as ve:
            return ve.message, section

    elif ('remove_obj' in form):
        fw_object = config(**{
            'id': form.get('obj_id', DATA.MISSING)
        })

        if (DATA.MISSING in fw_object.values()):
            return INVALID_FORM, section

        try:
            with FWObjectManager() as obj_manager:
                obj_manager.remove(fw_object)
        except ValidationError as ve:
            return ve.message, section

    elif (section not in valid_sections or 'change_section' not in form):
        return INVALID_FORM, 'MAIN'

    return '', section

def get_and_format_rules(section: str) -> list[list]:
    firewall_rules = FirewallControl.cfirewall.view_ruleset(section)

    converted_rules: list = []
    converted_rules_append = converted_rules.append

    with FWObjectManager(lookup=True) as object_manager:

        lookup = object_manager.lookup
        # convert rules into a friendly format
        for rule in firewall_rules.values():

            converted_rules_append([
                rule['enabled'], rule['name'],

                [lookup(x) for x in rule['src_zone']],
                [lookup(x) for x in rule['src_network']],
                [lookup(x) for x in rule['src_service']],

                [lookup(x) for x in rule['dst_zone']],
                [lookup(x) for x in rule['dst_network']],
                [lookup(x) for x in rule['dst_service']],

                rule['action'], rule['log'],
                rule['ipp_profile'], rule['dns_profile'], rule['ips_profile']
            ])

    return converted_rules

def calculate_ref_counts(firewall_rules: list[list]) -> None:

    rule: list
    zone: FW_OBJECT

    for rule in firewall_rules:

        src_zones: list[FW_OBJECT] = rule[2]
        dst_zones: list[FW_OBJECT] = rule[5]

        # increment every time a zone is used in a rule. default dict protects new zones ints.
        for zone in [*src_zones, *dst_zones]:
            reference_counts[zone.name.split('_')[0]] += 1

def commit_rules(json_data: dict[str, str]) -> return_data:

    section: str = json_data.get('section', '')
    if (not section or section not in valid_sections):
        return False, {'error': 1, 'message': 'missing section data'}

    if not json_data.get('rules', None):
        return False, {'error': 2, 'message': 'missing rule data'}

    # NOTE: all rules must be validated for any changes to be applied. validation will raise exception on first error.
    try:
        validated_rules = {section: validate_firewall_commit(json_data['rules'])}
    except ValidationError as ve:
        return False, {'error': 3, 'message': str(ve)}

    else:
        FirewallControl.commit(validated_rules)

    return True, {'error': 0, 'message': 'commit successful'}


# ================
# VALIDATION
# ================
class rule_structure(_NamedTuple):
    enabled: str
    name: str
    src_zone: str
    src_network: str
    src_service: str
    dst_zone: str
    dst_network: str
    dst_service: str
    action: str
    log: str
    sec1_prof: str
    sec2_prof: str
    sec3_prof: str

def validate_firewall_commit(fw_rules_json: str, /):
    # ["1", "lan_dhcp_allow", "lan", "tv,lan_network tv,dmz_network", "track_changes,udp_any", "any",
    #  "tv,lan_network tv,dmz_network", "track_changes,udp_67", "ACCEPT", "OFF", "0", "0"]

    fw_rules: dict = json.loads(fw_rules_json)

    validated_rules: dict = {}

    # TODO: make zone map integrated more gooder
    dnx_interfaces = load_configuration('system').get_items('interfaces->builtins')

    # TODO: same as above. not needed?
    lzone_map: dict[str, int] = {zone_name: zone_info['zone'] for zone_name, zone_info in dnx_interfaces}
    # 99 used to specify wildcard/any zone match
    lzone_map['any'] = ANY_ZONE

    with FWObjectManager(lookup=True) as object_manager:

        # index/ enumerate is for providing better feedback if issues are detected.
        for i, rule in enumerate(fw_rules.values(), 1):

            try:
                rule: rule_structure = rule_structure(*rule)
            except ValueError:  # i think its a value error
                raise ValidationError(f'Format error found in rule #{i}')

            try:
                validated_rules[i] = validate_firewall_rule(i, rule, object_manager.iter_validate)
            except ValidationError:
                raise

    return validated_rules

# NOTE: log disabled in form and set here as default for the time being.
def validate_firewall_rule(rule_num: int, fw_rule: rule_structure, /, check: Callable[[...], ...]) -> dict[str, Any]:

    actions: dict[str, int] = {'accept': 1, 'drop': 0}

    action = actions.get(fw_rule.action, DATA.INVALID)
    if (not action):
        raise ValidationError(f'{INVALID_FORM} [rule #{rule_num}/action]')

    ip_proxy_profile  = convert_int(fw_rule.sec1_prof)
    dns_proxy_profile = convert_int(fw_rule.sec2_prof)
    ips_ids_profile   = convert_int(fw_rule.sec3_prof)
    if not all([x in [0, 1] for x in [ip_proxy_profile, dns_proxy_profile, ips_ids_profile]]):
        raise ValidationError(f'Invalid security profile for rule #{rule_num}.')

    enabled = convert_int(fw_rule.enabled)

    # OBJECT VALIDATIONS
    src_zone = check(fw_rule.src_zone)
    if (INVALID_OBJECT in src_zone):
        raise ValidationError(f'A source zone object was not found for rule #{rule_num}.')

    src_network = check(fw_rule.src_network)
    if (INVALID_OBJECT in src_network):
        raise ValidationError(f'A source network object was not found for rule #{rule_num}.')

    src_service = check(fw_rule.src_service)
    if (INVALID_OBJECT in src_service):
        raise ValidationError(f'A source service object was not found for rule #{rule_num}.')

    dst_zone = check(fw_rule.dst_zone)
    if (INVALID_OBJECT in dst_zone):
        raise ValidationError(f'A destination zone object was not found for rule #{rule_num}.')

    dst_network = check(fw_rule.dst_network)
    if (INVALID_OBJECT in dst_network):
        raise ValidationError(f'A destination network object was not found for rule #{rule_num}.')

    dst_service = check(fw_rule.dst_service)
    if (INVALID_OBJECT in dst_service):
        raise ValidationError(f'A destination service object was not found for rule #{rule_num}.')

    rule = {
        'name': fw_rule.name,
        'id': None,
        'enabled': enabled,
        'src_zone': src_zone,                # [12]
        'src_network': src_network,
        'src_service': src_service,
        'dst_zone': dst_zone,                # [11]
        'dst_network': dst_network,
        'dst_service': dst_service,
        'action': action,                    # 1
        'log': 0,
        'ipp_profile': ip_proxy_profile,
        'dns_profile': dns_proxy_profile,
        'ips_profile': ips_ids_profile
    }

    return rule


valid_types = ['address', 'service', 'geolocation']
valid_service_chars = string.ascii_letters + string.digits + '/:-'
def validate_object(obj: config) -> Optional[ValidationError]:
    # 'id', 'name', 'type', 'value', 'desc'
    if (obj.id and obj.id not in range(*USER_RANGE)):
        return ValidationError('object id falls outside of usable range.')

    try:
        standard(obj.name, override=['_'])
        full_field(obj.desc)
    except ValidationError as ve:
        return ve

    # autofill was pissing me off.
    object_value = obj.value
    if (obj.type == 'address'):

        # ADDRESS TYPE 2 (NETWORK)
        if ('/' in object_value):
            obj.subtype = 2
            try:
                ip_network(object_value)
            except ValidationError as ve:
                return ve

        # ADDRESS TYPE 1 (HOST)
        else:
            obj.subtype = 1
            obj.value += '/32'  # makes backend code simpler
            try:
                ip_address(object_value)
            except ValidationError as ve:
                return ve

    elif (obj.type == 'service'):
        # quick once over for basic alphanum and service symbols
        for i, c in enumerate(obj.type, 1):
            if c in valid_service_chars:
                continue

            return ValidationError(f'Invalid character for type "service" -> {c} in pos {i}')

        # SERVICE TYPE 3 (LIST)
        if (':' in object_value):
            obj.subtype = 3
            # range nested within the list. we should implement this at some point.
            if ('-' in object_value):
                return ValidationError('Service ranges are not currently supported in a service list.')

            services = object_value.split(':')
            for service in services:
                try:
                    proto_port(service)
                except ValidationError as ve:
                    return ve

        # SERVICE TYPE 1 (SINGLE) & 2 (RANGE)
        else:
            try:
                proto_port(object_value)
            except ValidationError as ve:
                return ve

            obj.subtype = 2 if '-' in object_value else 1

    # not currently supported
    elif (obj.type == 'geolocation'):
        return ValidationError('Geolocation lists are current not supported.')

    else:
        return ValidationError(f'Valid object types are {", ".join(valid_types)}')
