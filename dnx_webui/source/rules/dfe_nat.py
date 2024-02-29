#!/usr/bin/python3

from __future__ import annotations

from subprocess import run

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_enums import CFG, DATA
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config

from dnx_iptools.iptables import IPTablesManager
from dnx_gentools.system_info import System

from source.web_interfaces import RulesWebPage

__all__ = ('WebPage',)


class WebPage(RulesWebPage):
    @staticmethod
    def load(_: Form) -> dict[str, Any]:
        return {
            'dmz_dnat_rules': System.nat_rules(),
            'local_snat_rules': System.nat_rules(nat_type='SRCNAT')
        }

    @staticmethod
    def update(form: Form) -> tuple[str, str]:

        # the action field is not required for some functions, so it will not be hard checked
        action = form.get('action', DATA.MISSING)

        nat_type = form.get('nat_type', DATA.MISSING)
        if (nat_type == 'DSTNAT'):
            error = _dnat_rules(form, action)

        elif (nat_type == 'SRCNAT'):
            error = _snat_rules(form, action)

        else:
            return INVALID_FORM + ' code=99', ''

        return error, ''

# TODO: currently it is possible to put overlapping DNAT rules (same dst port, but different host port).
#  this isnt normally an issue, but the last one inserted will be the local port value in cfg.
#  if the more recent rule is the lower rule, it will be incorrect for portscan reject packets.
#  a similar issue will also be for the local ports because they are flipped when loaded into the ips.
    # NOTE: a possible solution would be to store the wan ip/wan port and local ip/ local port in a tuple
    # or a splittable string. this could be the key/vals to the dict making each unique and would allow
    # for any combination and still properly identify missed scans while also reliable generating reject
    # packets.
def _dnat_rules(form: Form, action: str) -> str:

    fields = config(**form)
    if (action == 'add'):
        # checking all required fields are present and some other basic rules are followed
        # before validating values of standard fields.
        if error := validate_dnat_rule(fields, action=CFG.ADD):
            return error.message + ' code=1'

        if (fields.protocol in ['tcp', 'udp']):
            try:
                network_port(fields.dst_port)
                network_port(fields.host_port)

                ip_address(fields.host_ip)

                if (fields.dst_ip != ''):
                    ip_address(fields.dst_ip)

            except ValidationError as ve:
                return ve.message + ' code=2'

        with IPTablesManager() as iptables:
            iptables.add_nat(fields)

            configure_open_wan_protocol(fields, action=CFG.ADD)

    elif (action == 'remove'):
        fields.position = convert_int(fields.position)

        # NOTE: validation needs to know the zone, so it can ensure the position is valid
        if error := validate_dnat_rule(fields, action=CFG.DEL):
            return error.message + ' code=3'

        with IPTablesManager() as iptables:
            iptables.delete_nat(fields)

            configure_open_wan_protocol(fields, action=CFG.DEL)

    else:
        return INVALID_FORM + ' code=98'

    return ''

def _snat_rules(form: Form, action: str) -> str:
    # TODO: make this code for snat (currently using dnat code as template)

    fields = config(**form)
    if (action == 'add'):

        if error := validate_snat_rule(fields, action=CFG.ADD):
            return error.message + ' code=4'

        try:
            ip_address(ip_iter=[fields.orig_src_ip, fields.new_src_ip])
        except ValidationError as ve:
            return ve.message + ' code=5'

        with IPTablesManager() as iptables:
            iptables.add_nat(fields)

    elif (action == 'remove'):
        fields.position = convert_int(fields.position)

        # NOTE: validation needs to know the zone, so it can ensure the position is valid
        if error := validate_snat_rule(fields, action=CFG.DEL):
            return error.message + ' code=6'

        with IPTablesManager() as iptables:
            iptables.delete_nat(fields)

    else:
        return INVALID_FORM + ' code=99'

    return ''

# ===========
# VALIDATION
# ===========
def validate_dnat_rule(rule: config, /, action: CFG) -> Optional[ValidationError]:

    if (action is CFG.ADD):
        # ensuring all necessary fields are present in the namespace before continuing.
        valid_fields = [
            'src_zone', 'dst_ip', 'dst_port', 'host_ip', 'host_port', 'protocol'
        ]

        if not all([hasattr(rule, x) for x in valid_fields]):
            return ValidationError(INVALID_FORM)

        if (rule.protocol not in ['tcp', 'udp', 'icmp']):
            return ValidationError(INVALID_FORM)

        if (not rule.dst_ip and rule.dst_port in ['443', '80']):
            return ValidationError('Ports 80,443 cannot be set as destination port when destination IP is not set.')

        if (rule.protocol == 'icmp'):

            open_protocols: ConfigChain = load_configuration('global', cfg_type='security/ids_ips')
            if (open_protocols['open_protocols->icmp']):
                return ValidationError(
                    'Only one ICMP rule can be active at a time. Remove existing rule before adding another.'
                )

    elif (action is CFG.DEL):
        output = run(
            f'sudo iptables -t nat -nL {rule.nat_type} --line-number', shell=True, capture_output=True
        ).stdout.splitlines()[1:]

        rule_count = len(output)
        if (rule.position not in range(1, rule_count + 1)):
            return ValidationError('Selected rule is not valid and cannot be removed.')

        # validating fields for removing the associated open protocol/port from the tracker
        try:
            rule.protocol, rule.port = rule.proto_port.split('/')
        except:
            return ValidationError(INVALID_FORM)

        open_protocol_settings: ConfigChain = load_configuration('global', cfg_type='security/ids_ips')
        # check tcp/udp first, then icmp if it fails.
        # if either fail, standard exception raised.
        try:
            open_protocol_settings[f'open_protocols->{rule.protocol}->{rule.port}']
        except:
            if (rule.protocol != 'icmp' and rule.port != '0'):
                return ValidationError(INVALID_FORM)

def validate_snat_rule(rule: config, /, action: CFG) -> Optional[ValidationError]:

    if (action is CFG.ADD):
        # ensuring all necessary fields are present in the namespace before continuing.
        valid_fields = [
            'src_zone', 'orig_src_ip', 'new_src_ip'
        ]

        if not all([hasattr(rule, x) for x in valid_fields]):
            return ValidationError('Invalid form.')

# ==============
# CONFIGURATION
# ==============
def configure_open_wan_protocol(nat: config, *, action: CFG) -> None:
    with ConfigurationManager('global', cfg_type='security/ids_ips') as dnx:
        protocol_settings: ConfigChain = dnx.load_configuration(strict=False)

        if (action is CFG.ADD):

            # if dst port is specified, protocol is tcp/udp
            if (nat.dst_port):
                protocol_settings[f'open_protocols->{nat.protocol}->{nat.dst_port}'] = nat.host_port

            # will only match icmp, which is configured as a boolean value
            else:
                protocol_settings[f'open_protocols->{nat.protocol}'] = True

        elif (action is CFG.DEL):

            if (nat.protocol == 'icmp'):
                protocol_settings['open_protocols->icmp'] = False

            else:
                del protocol_settings[f'open_protocols->{nat.protocol}->{nat.port}']

        dnx.write_configuration(protocol_settings.expanded_user_data)
