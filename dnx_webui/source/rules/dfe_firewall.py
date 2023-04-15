#!/usr/bin/python3

from __future__ import annotations

import json
import string

from typing import NamedTuple as _NamedTuple
from collections import defaultdict

from source.web_typing import *
from source.web_validate import *
from source.object_manager import FWObjectManager, USER_RANGE

from dnx_gentools.def_enums import DATA
from dnx_gentools.file_operations import load_configuration, config

from dnx_secmods.cfirewall.fw_control import FirewallControl

from source.web_interfaces import RulesWebPage

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_namedtuples import FW_OBJECT

__all__ = ('WebPage',)

cfirewall = FirewallControl.cfirewall

valid_sections = {'BEFORE': '1', 'MAIN': '2', 'AFTER': '3'}

reference_counts = defaultdict(int)
zone_map = {'builtin': {}, 'extended': {}}
zone_manager = {'builtin': {}, 'user-defined': {}}

INVALID_OBJECT = -1
VALID_RULE_IDS = [1000, 10000]

TRAFFIC_LOG  = {'on': 1, 'off': 0}
RULE_ACTIONS = {'accept': 1, 'drop': 0}

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

class WebPage(RulesWebPage):
    @staticmethod
    def load(section: str) -> dict[str, Any]:
        lzone_map: dict[int, str] = {ANY_ZONE: 'any'}

        dnx_settings: ConfigChain = load_configuration('system', cfg_type='global')

        # building out interface to zone map NOTE: builtins only for now
        for intf_type in ['builtin', 'extended']:
            for intf_name, intf_info in dnx_settings.get_items(f'interfaces->{intf_type}'):
                ident = intf_info['ident']

                zone_map[intf_type][ident] = intf_name

                # need to make converting zone ident/int to name easier in format function
                zone_ident = dnx_settings[f'zones->builtin->{intf_name}'][0]

                # TODO: is lzone_map needed after moving zones to fw objects?
                lzone_map[zone_ident] = intf_name

        reference_counts.clear()
        # NOTE: this needs to be before the zone manager builds, so we can get reference counts
        firewall_rules = get_and_format_rules(section)

        # TODO: this is now unoptimized.
        #  we should track ref counts in in FirewallControl class and inc/dec when rule is deleted or added.
        # calculate_ref_counts(firewall_rules)

        # building zone list and reference counts NOTE: builtins only for now
        for zone_type in ['builtin', 'user-defined']:
            for zone_name, (zone_ident, zone_desc) in dnx_settings.get_items(f'zones->{zone_type}'):

                zone_manager[zone_type][zone_name] = [reference_counts[zone_name], zone_desc]

        version: int
        firewall_objects: dict[str, list]
        version, firewall_objects = FWObjectManager.get_objects()

        # fw_object_map: dict[str, dict] = {obj.name: {'type': obj.type, 'id': obj.id} for obj in firewall_objects}
        fw_object_map = {o[1]: format_fw_obj(o) for o in firewall_objects.values()}

        # FIXME: this is redundant, but needed to rendering the firewall object list.
        #  this should only be used for jinja at least it shouldn't be getting sent to client.
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
            'pending_changes': cfirewall.is_pending_changes()
        }

    @staticmethod
    def update(form: Form) -> tuple[str, str]:

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
                return INVALID_FORM + '. code=1', section

            if error := validate_object(fw_object):
                return error.message + '. code=2', section

            try:
                with FWObjectManager() as obj_manager:
                    obj_manager.add(fw_object)
            except ValidationError as ve:
                return ve.message + '. code=3', section

        elif ('edit_obj' in form):
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
                return INVALID_FORM + '. code=4', section

            if error := validate_object(fw_object):
                return error.message + '. code=5', section

            try:
                with FWObjectManager() as obj_manager:
                    obj_manager.update(fw_object)
            except ValidationError as ve:
                return ve.message + '. code=6', section

        elif ('remove_obj' in form):
            fw_object = config(**{
                'id': get_convert_int(form, 'obj_id')
            })

            if (DATA.MISSING in fw_object.values()):
                return INVALID_FORM + '. code=7', section

            try:
                with FWObjectManager() as obj_manager:
                    obj_manager.remove(fw_object)
            except ValidationError as ve:
                return ve.message + '. code=8', section

        elif (section not in valid_sections or 'change_section' not in form):
            return INVALID_FORM + '. code=9', 'MAIN'

        return '', section

    @staticmethod
    def handle_ajax(json_data: dict[str, str]) -> return_data:

        section: str = json_data.get('section', '')
        if (not section or section not in valid_sections):
            return False, {'error': 1, 'message': 'missing section data'}

        if not json_data.get('rules', None):
            return False, {'error': 2, 'message': 'missing rule data'}

        # NOTE: all rules must be validated for changes to be applied. validation will raise exception on first error.
        try:
            validated_rules = validate_firewall_commit(json_data['rules'])
        except ValidationError as ve:
            return False, {'error': 3, 'message': str(ve)}

        else:
            cfirewall.commit(section, validated_rules)

        return True, {'error': 0, 'message': 'commit successful'}

def get_and_format_rules(section: str) -> list[list]:
    firewall_rules = cfirewall.view_ruleset(section)

    converted_rules: list = []
    converted_rules_append = converted_rules.append

    with FWObjectManager(lookup=True) as object_manager:

        lookup = object_manager.lookup
        # convert rules into a friendly format
        for rule in firewall_rules.values():

            converted_rules_append([
                rule['enabled'], rule['id'], rule['name'],

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


# ================
# VALIDATION
# ================
class rule_structure(_NamedTuple):
    enabled: str
    id: str
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
    # ["1", "6969", "lan_dhcp_allow", "lan", "tv,lan_network tv,dmz_network", "track_changes,udp_any", "any",
    #  "tv,lan_network tv,dmz_network", "track_changes,udp_67", "ACCEPT", "OFF", "0", "0"]

    fw_rules: dict = json.loads(fw_rules_json)

    validated_rules: dict = {}

    # TODO: make zone map integrated more gooder
    dnx_interfaces = load_configuration('system', cfg_type='global').get_items('interfaces->builtin')

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

def validate_firewall_rule(rule_num: int, fw_rule: rule_structure, /, check: Callable[[str], list[int]]) -> dict[str, Any]:

    if ((tlog := TRAFFIC_LOG.get(fw_rule.log, DATA.MISSING)) is DATA.MISSING):
        raise ValidationError(f'{INVALID_FORM} [rule #{rule_num}/log]')

    if ((action := RULE_ACTIONS.get(fw_rule.action, DATA.MISSING)) is DATA.MISSING):
        raise ValidationError(f'{INVALID_FORM} [rule #{rule_num}/action]')

    if ((enabled := convert_bint(fw_rule.enabled)) is DATA.INVALID):
        raise ValidationError(f'Invalid value in "enabled" field for rule #{rule_num}')

    r_id = convert_int(fw_rule.id)
    if (r_id is DATA.INVALID or (r_id != 0 and r_id not in range(*VALID_RULE_IDS))):
        raise ValidationError(f'Invalid value in "id" field for rule #{rule_num}')

    rule = {
        'name': standard(fw_rule.name, override=['_']),
        'id': r_id,
        'enabled': enabled,
        'src_zone': check(fw_rule.src_zone),                # [12]
        'src_network': check(fw_rule.src_network),
        'src_service': check(fw_rule.src_service),
        'dst_zone': check(fw_rule.dst_zone),                # [11]
        'dst_network': check(fw_rule.dst_network),
        'dst_service': check(fw_rule.dst_service),
        'action': action,                    # 1
        'log': tlog,
        'ipp_profile': convert_int(fw_rule.sec1_prof),
        'dns_profile': convert_int(fw_rule.sec2_prof),
        'ips_profile': convert_int(fw_rule.sec3_prof)
    }

    # SECURITY PROFILE VALIDATIONS - currently restricted to 0/1
    if any([rule[profile] not in [0, 1] for profile in ['ipp_profile', 'dns_profile', 'ips_profile']]):
        raise ValidationError(f'Invalid security profile for rule #{rule_num}.')

    # OBJECT VALIDATIONS
    for obj in ['src_zone', 'src_network', 'src_service', 'dst_zone', 'dst_network', 'dst_service']:
        if (INVALID_OBJECT in rule[obj]):
            raise ValidationError(f'A {obj.replace("_", " ")} object was not found for rule #{rule_num}.')

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
                return ValidationError('Service ranges are currently not supported in a service list.')

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
        return ValidationError('Geolocation lists are currently not supported.')

    else:
        return ValidationError(f'Valid object types are {", ".join(valid_types)}')
