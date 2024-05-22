#!/usr/bin/env python3

from __future__ import annotations

import re
import string

from types import MappingProxyType
from typing import NamedTuple
from ipaddress import IPv4Network, IPv4Address

# TODO: consider moving this module, web_typing, and web_interfaces to dnx_webui folder instead of source
from dnx_webui.source.web_typing import *

web_module_load_callout(__file__)

from dnx_gentools.def_constants import WEBUI_DEVELOPMENT
from dnx_gentools.def_enums import CFG, DATA, PROTO
from dnx_gentools.def_exceptions import DNXError
from dnx_gentools.file_operations import config


BINT = (0, 1)

MIN_PORT = 1
MAX_PORT = 65535
MAX_PORT_RANGE = MAX_PORT + 1

__all__ = (
    'SKIP_VALIDATION',
    'ValidationError', 'ValidationPageContext',
    'ValidationConfigForm', 'ValidationFieldContext', 'ValidationFieldInfo',

    'INVALID_FORM', 'NO_STANDARD_ERROR',
    'VALID_MAC', 'VALID_DOMAIN',

    'check_digit', 'check_bint', 'check_in_range',

    'convert_int', 'get_convert_int',
    'convert_bint', 'get_convert_bint',
    'convert_in_range', 'get_convert_in_range',
    'check_in_options_int',

    'alpha_maxlen', 'alphanum_maxlen',
    'standard', 'full_field',

    'mac_address',
    'ip_address', 'default_gateway', 'ip_network', 'cidr',
    'network_port', 'proto_port',

    'domain_name',
    'add_ip_whitelist',
)

SKIP_VALIDATION = object()  # form field level sentinel

class ValidationError(DNXError):
    '''Webui processing failure or invalid user input.'''

class ValidationPageContext(NamedTuple):
    '''Used for global on_enter and on_exit sections in ValidationConfigForm.parse_form.

    can be used to run validation that will apply to all forms/submissions or append a key/value into cfg data.

    call:   func(type[Form|config]) -> Optional[ValidationError] -- function hook
    append: func(type[Form, config]) -> Optional[ValidationError] -- add/remove from config data [defaults is a no-op]
    '''
    call: Callable[[Form|config], Optional[ValidationError]]
    append: Callable[[Form, config], Optional[ValidationError]] = lambda x, y: None


class ValidationFieldContext(NamedTuple):
    '''Used for on_enter and on_exit sections in ValidationConfigForm.parse_form

    call: func(type[Form|config]) -- function hook
    '''
    call: Callable[[Form|config], Optional[ValidationError]]

class ValidationFieldInfo(NamedTuple):
    '''
    cfg_key: str -- name used when adding the form value to a config object
    error_msg: str -- message returned to client (if not provided, language default will be used)
    format: func(str)|None -- basic function to check string conformity (ex: str.isdigit)
    validation: func(str) -- function to check system/config rule conformity
    convert: func(str) -- convert form value from str to config type [default is a no-op]
    '''
    cfg_key: str
    error_msg: Optional[str] = None
    format: Callable[[str], Optional[ValidationError]] = None
    validation: Callable[[str], Optional[ValidationError]] = None
    convert: Callable[[str], Any] = lambda x: x

ValidationPageContexts: TypeAlias = dict[str, ValidationPageContext]
FormButtonName = str
FormFieldName = str
ValidationPageForms_T: TypeAlias = dict[FormButtonName, dict[FormFieldName, ValidationFieldInfo|ValidationFieldContext]]
ValidationPageForms_P: TypeAlias = MappingProxyType[FormButtonName, dict[FormFieldName, ValidationFieldInfo|ValidationFieldContext]]

class ValidationConfigForm:
    '''Configuration class for storing configuration key/value pairs.

    provides validation and other utility methods for configuration data.

    on_enter -> can be used to disable handling of a config form submission
    on_exit -> can be used to validate combined fields
    '''
    BUTTON_KEY = 'vbtn'

    __slots__ = ('page_forms',)

    def __init__(self, page_forms: ValidationPageForms_T):
        self.page_forms: ValidationPageForms_P = MappingProxyType(page_forms)

    def parse_form(self, form: Form) -> tuple[Optional[ValidationError], Optional[config]]:
        '''parses a form and returns a config object.

        returns a tuple containing an error and a config object.
        '''
        btn_name = form.get(self.BUTTON_KEY, DATA.MISSING)
        if (btn_name is DATA.MISSING):
            return ValidationError('Missing form action.'), None

        # -security: stripping "_" to prevent injected form data from matching on_enter and on_exit global contexts.
        form_profile = self.page_forms.get(btn_name.strip('_'), DATA.MISSING)
        if (form_profile is DATA.MISSING):
            return ValidationError('Unspecified form submitted.'), None

        cfg = config()

        # ==================================================
        # PAGE ON ENTER - applies to all forms
        # ==================================================
        page_on_enter: Optional[ValidationPageContexts]
        if page_on_enter := self.page_forms.get('__on_enter', None):
            for context_name, context_profile in page_on_enter.items():
                conxtext_friedly_name = context_name.replace('_', ' ')

                if error := context_profile.call(form):
                    return ValidationError(f'{conxtext_friedly_name}: {error.message}'), None

                if error := context_profile.append(form, cfg):
                    return ValidationError(f'{conxtext_friedly_name}: {error.message}'), None  # lambda typing issue

        # needed to register form submissions that are validated at page level __on_enter
        if (form_profile is SKIP_VALIDATION):
            cfg.btn = btn_name
            return None, cfg

        # ==================================================
        # FORM SUBMISSION PROCESSING
        # ==================================================
        for field_name, field_profile in form_profile.items():

            field_friedly_name = field_name.replace('_', ' ')

            # context fields/ function calls
            if (field_name == '_on_enter'):
                if error := field_profile.call(form):
                    return error, None

                continue

            elif (field_name == '_on_exit'):
                if error := field_profile.call(cfg):
                    return error, None

                break

            field_value = form.get(field_name, DATA.MISSING)
            if (field_value is DATA.MISSING):
                return ValidationError(f'Missing form field [{field_name}].'), None

            # field format check will generally raise an exception, but added support for returning instead
            if (field_profile.format):
                try:
                    if err := field_profile.format(field_value):
                        return ValidationError(f'{field_friedly_name}: {field_profile.error_msg or err.args[0]}'), None
                except Exception as err:
                    return ValidationError(f'{field_friedly_name}: {field_profile.error_msg or err.args[0]}'), None

            # field validation returns exception as value only
            if (field_profile.validation):
                if error := field_profile.validation(field_value):
                    return ValidationError(f'{field_friedly_name}: {error.message}'), None

            cfg[field_profile.cfg_key] = field_profile.convert(field_value)

        # ==================================================
        # PAGE ON EXIT - applies to all forms
        # ==================================================
        page_on_exit: Optional[ValidationPageContext]
        if page_on_exit := form.get('__on_exit', None):
            if error := page_on_exit.call(cfg):
                return error, None

            if error := page_on_exit.append(form, cfg):
                return error, None

        # unhandled form data. should only happen if the form is tampered with client side.
        # if (form):
        #     return ValidationError('Non-conforming form data present.'), None

        # appending button name to select correct configuration function
        cfg.btn = btn_name

        if (WEBUI_DEVELOPMENT):
            print(f'Config data\n{"="*16}\n{cfg}')

        return None, cfg


_proto_map = {'any': 0, 'icmp': 1, 'tcp': 6, 'udp': 17}

NO_STANDARD_ERROR: tuple[int, str] = (0, '')
NO_LOG_ERROR: tuple[str, str, []] = ('', '', [])
INVALID_FORM: str = 'Invalid form data.'
INVALID_TYPE = ValidationError('Invalid field type.')

# TODO: mac regex allows trailing characters. it should hard cut after the exact char length.
VALID_MAC = re.compile('(?:[0-9a-fA-F]:?){12}')
VALID_DOMAIN = re.compile('(//|\\s+|^)(\\w\\.|\\w[A-Za-z0-9-]{0,61}\\w\\.){1,3}[A-Za-z]{2,6}')

# to be used with the new form validation system
def check_digit(s: str) -> Optional[ValidationError]:
    if not s.isdigit():
        return INVALID_TYPE

def check_bint(s: str) -> Optional[ValidationError]:
    if s not in ['0', '1']:
        return INVALID_TYPE

def check_in_range(s: str, r: tuple[int, int]) -> Optional[ValidationError]:
    '''note: both ends of the bounds are inclusive.
    '''
    try:
        i_s = int(s)
    except ValueError:
        return INVALID_TYPE

    if i_s not in range(r[0], r[1] + 1):
        return ValidationError(f'Selection must be within range [{r[0]}, {r[1]}].')

def check_in_options_int(s: str, o: tuple) -> Optional[ValidationError]:
    try:
        i_s = int(s)
    except ValueError:
        return INVALID_TYPE

    if i_s not in o:
        return ValidationError(f'Selection must be within options {list(o)}.')

def get_convert_int(form: Union[Form, Args], key: str) -> Union[int, DATA]:
    '''gets string value from submitted form then converts into an integer and returns.

    If the key is not present or string cannot be converted, an IntEnum representing the error will be returned.
    '''
    value = form.get(key, DATA.MISSING)
    try:
        return value if value == DATA.MISSING else int(value)
    except:
        return DATA.INVALID

def get_convert_bint(form: Form, key: str) -> Union[int, DATA]:
    '''convenience wrapper around convert_bint().

    calls val = form.get(key) then returns the result of convert_bint(val).
    '''
    value = form.get(key, None)

    return convert_bint(value)

def get_convert_in_range(form: Form | JSON, key: str, *, bounds: tuple[int, int] = (0, 1)) -> int | DATA:
    '''gets value for specified key, converts to an int, then returns if the resulting int is within specified range.

        note: both ends of the bounds are inclusive.
    '''
    value = form.get(key, DATA.MISSING)

    if value is DATA.MISSING:
        return value

    try:
        return int(value) if int(value) in range(bounds[0], bounds[1] + 1) else DATA.INVALID
    except:
        return DATA.INVALID

def convert_bint(num: Union[str, bool]) -> Union[int, DATA]:
    '''converts argument into an integer representation of bool.

    DATA.INVALID (-1) will be returned on error.
    '''
    try:
        bint = int(num)
    except TypeError:
        return DATA.INVALID

    return bint if bint in BINT else DATA.INVALID

def convert_float(num: str) -> Union[float, DATA]:
    '''converts argument into a float, then returns. DATA.INVALID (-1) will be returned on error.
    '''
    try:
        return float(num)
    except:
        return DATA.INVALID

def convert_int(num: Union[str, bool]) -> Union[int, DATA]:
    '''converts argument into an integer, then returns.

    DATA.INVALID (-1) is returned on error.
    '''
    try:
        return int(num)
    except:
        return DATA.INVALID

def convert_in_range(num: str, bounds: tuple[int, int] = (0, 1)) -> int | DATA:
    '''converts argument into an integer, then returns if it falls within the specified range.

    DATA.INVALID (-1) is returned on error.

        note: both ends of the bounds are inclusive.
    '''
    try:
        return int(num) if int(num) in range(bounds[0], bounds[1] + 1) else DATA.INVALID
    except:
        return DATA.INVALID

def alpha_maxlen(s: str, *, maxlen: int, override: Optional[list] = None) -> Optional[ValidationError]:
    '''checks if a string contains only alpha characters and is within the specified length.

    override can be used to allow additional characters in the string.
    '''
    if (len(s) > maxlen):
        return ValidationError(f'Field length must be less than {maxlen} characters.')

    override = [] if override is None else override

    err_msg  = 'Field can only contain contain characters in the alphabet'
    err_msg += f'or the following {override}.' if override else '.'

    for char in s:
        if (not char.isalpha() and char not in override):
            return ValidationError(err_msg)

def alphanum_maxlen(s: str, *, maxlen: int, override: Optional[list] = None) -> Optional[ValidationError]:
    '''checks if a string contains only alpha and numeric characters and is within the specified length.

    override can be used to allow additional characters in the string.
    '''
    if (len(s) > maxlen):
        return ValidationError(f'Field length must be less than {maxlen} characters.')

    overrides = [*string.digits] if override is None else [override, string.digits]

    err_msg  = 'Field can only contain contain characters in the alphabet or digits 0-9'
    err_msg += f'or the following {override}.' if override else '.'

    for char in s:
        if (not char.isalnum() and char not in overrides):
            return ValidationError(err_msg)

def standard(user_input: str, *, override: Optional[list] = None) -> str:
    override = [] if override is None else override

    for char in user_input:
        if (not char.isalnum() and char not in override):
            raise ValidationError(
                f'Standard fields can only contain alpha numeric characters or the following {", ".join(override)}.'
            )

    return user_input

def full_field(user_input: str, ftype: str = 'Description') -> None:
    valid_chars = f' {string.printable.strip(string.whitespace)}'

    for char in user_input:
        if (char in valid_chars):
            continue

        raise ValidationError(f'{ftype} fields dont support tabs, returns, or linebreaks.')

def syslog_dropdown(syslog_time):
    syslog_time = convert_int(syslog_time)
    if (syslog_time):
        raise ValidationError('Dropdown values must be an integer.')

    if (syslog_time not in [5, 10, 60]):
        raise ValidationError('Dropdown values can only be 5, 10, or 60.')

def mac_address(mac):
    if (not VALID_MAC.match(mac)):
        raise ValidationError('MAC address is not valid.')

def _ip_address(ip_addr):
    try:
        ip_addr = IPv4Address(ip_addr)
    except:
        raise ValidationError('IP address is not valid.')

    if (ip_addr.is_loopback):
        raise ValidationError('127.0.0.0/24 is reserved ip space and cannot be used.')

# this is a convenience wrapper around above function to allow for multiple ips to be checked with one func call.
def ip_address(ip_addr: Optional[str] = None, *, ip_iter: Optional[list['str']] = None) -> None:
    '''raises a ValidationError if the ip address is not valid.

    ip_iter can be used to check multiple with a single call and will raise Validation error on first invalid ip.
    '''
    ip_iter = [ip_addr] if not ip_iter else ip_iter
    if (not isinstance(ip_iter, list)):
        raise ValidationError('Data format must be a list.')

    for ip in ip_iter:
        _ip_address(ip)

def ip_network(net: str, /) -> None:
    try:
        ip_netw = IPv4Network(net)
    except:
        raise ValidationError('IP network is not valid.')

def default_gateway(ip_addr, /):
    try:
        ip_addr = IPv4Address(ip_addr)
    except:
        raise ValidationError('Default gateway is not valid.')

    if (ip_addr.is_loopback):
        raise ValidationError('Default gateway cannot be 127.0.0.1/loopback.')

def domain_name(dom: str, /):
    if (not VALID_DOMAIN.match(dom)):
        raise ValidationError('Domain is not valid.')

def cidr(cd: str, /) -> None:
    if (convert_int(cd) not in range(0, 33)):
        raise ValidationError('Netmask must be in range 0-32.')

# NOTE: split + iter is to support port ranges. limiting split to 1 to prevent 1:2:3 from being marked as valid.
def network_port(port, port_range=False):
    '''validates network ports 1-65535 or a range of 1-65535:1-65535
    '''
    if (port_range):
        ports = [convert_int(p) for p in port.split(':', 1)]
        additional = ' or a range of 1-65535:1-65535 '

    else:
        ports = [convert_int(port)]
        additional = ''

    if (len(ports) == 2):
        if (ports[0] >= ports[1]):
            raise ValidationError('Invalid range, the start value must be less than the end. ex. 9001:9002')

    for port in ports:

        if (port not in range(1, 65536)):
            raise ValidationError(f'TCP/UDP port must be between 1-65535{additional}.')

def proto_port(port_str):

    try:
        proto, port = port_str.split('/')
    except:
        raise ValidationError('Invalid protocol/port definition. ex tcp/80 or udp/500-550')

    proto_int = _proto_map.get(proto, None)
    if (proto_int is None):
        raise ValidationError('Invalid protocol. Use [any, tcp, udp, icmp].')

    # ensuring icmp definitions conform to the required format.
    if (proto_int == PROTO.ICMP and convert_int(port) != 0):
        raise ValidationError('ICMP does not support ports. Use icmp/0.')

    # splitting str after the "/" on "-" which is port range operator. this will make range or singular definition
    # handling the same.
    ports = [convert_int(p) for p in port.split('-', 1)]

    if (len(ports) == 2):
        if (ports[0] > ports[1]):
            raise ValidationError('Invalid port range. The start value must be less than the end. ex. 9001-9002')

        error = f'TCP/UDP port range must be between within range 1-65535. ex tcp/500-550'

    else:
        # this puts single port in range syntax
        ports.append(ports[0])

        error = f'TCP/UDP port must be between 1-65535. ex udp/9001'

    # converting 0 port values to cover full range (0 is an alias for any). ICMP will not be converted to ensure
    # compatibility between icmp service definition vs any service. Any protocol will not be converted for same reason.
    if (proto_int not in [PROTO.ICMP, PROTO.ANY]):
        ports[0] = ports[0] if ports[0] != 0 else 1

    # expanding the range out for any. this does not cause issues with icmp since it does not use ports so the second
    # value in a port range is N/A for icmp, but in this case just letting it do what the others do.
    ports[1] = ports[1] if ports[1] != 0 else 65535

    for port in ports:

        # port 0 is used by icmp. if 0 is used outside icmp it gets converted to a range.
        if (port not in range(65536)):
            raise ValidationError(error)

    return proto_int, ports

def syslog_settings(settings, /):
    # syslog = load_configuration('syslog_client')

    return
    # configured_syslog_servers = syslog['servers']
    # if (not configured_syslog_servers):
    #     raise ValidationError('Syslog servers must be configured before modifying client settings.')
    #
    # tls_retry = convert_int(settings['tls_retry'])
    # tcp_retry = convert_int(settings['tcp_retry'])
    # tls_settings = settings['tls']
    # syslog_settings = settings['syslog']
    #
    # if (tls_retry not in [5, 10, 60] and tcp_retry not in [5, 10, 30]):
    #     raise ValidationError('Syslog settings are not valid.')
    #
    # for item in tls_settings:
    #     if (item not in ['enabled', 'tcp_fallback', 'udp_fallback', 'self_signed']):
    #         raise ValidationError('Syslog settings are not valid.')
    #
    # for item in syslog_settings:
    #     if (item not in ['syslog_enabled', 'syslog_protocol']):
    #         raise ValidationError('Syslog settings are not valid.')
    #
    # if ('syslog_protocol' not in syslog_settings):
    #     if ('encrypted_syslog' in tls_settings):
    #         raise ValidationError('TCP must be enabled to enable TLS.')
    #
    #     if ('tcp_fallback' in tls_settings):
    #         raise ValidationError('TLS must be enabled before TCP fallback.')

def management_access(fields):
    SERVICE_TO_PORT = {'webui': (80, 443), 'cli': (0,), 'ssh': (22,), 'ping': 1}

    if (fields.zone not in ['lan', 'dmz'] or fields.service not in ['webui', 'cli', 'ssh', 'ping']):
        raise ValidationError(INVALID_FORM)

    # convert_int will return -1  if issues with form data and ValueError will cover
    # invalid CFG action key/vals
    try:
        action = CFG(convert_int(fields.action))
    except ValueError:
        raise ValidationError(INVALID_FORM)

    fields.action = action
    fields.service_ports = SERVICE_TO_PORT[fields.service]

def add_ip_whitelist(settings, /):
    # handling alphanum check. will raise exception if invalid.
    standard(settings['user'])

    if (settings['type'] not in ['global', 'tor']):
        raise ValidationError(INVALID_FORM)

    # if ip is valid this will return, otherwise a ValidationError will be raised.
    _ip_address(settings['user'])
