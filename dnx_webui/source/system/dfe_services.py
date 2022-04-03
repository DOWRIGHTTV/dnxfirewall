#!/usr/bin/python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import INVALID_FORM, space_join
from dnx_gentools.def_enums import CFG
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config

from source.web_validate import convert_int, ValidationError
from dnx_routines.configure.system_info import Services
from dnx_routines.configure.iptables import IPTablesManager

from dnx_system.sys_action import system_action

DISABLED_MANAGEMENT_SERVICES = ['cli']

def load_page(form: dict) -> dict[str, Union[list, dict[dict[str, int]]]]:
    dnx_settings = load_configuration('system')

    all_services = []
    for service, desc in dnx_settings.get_items('services'):
        service = space_join((service.split('-')[1:]))

        all_services.append((service, desc, Services.status(service)))

    return {'all_services': all_services, 'mgmt_access': dnx_settings.get_dict('mgmt_access')}

def update_page(form: dict) -> Optional[str]:

    # checking if button keys are present in form is easy first line validation to ensure valid form fields
    if ('update_mgmt_access' in form):

        try:
            zone, service, action = form.get('update_mgmt_access').split(',')
        except:
            return INVALID_FORM

        if (service in DISABLED_MANAGEMENT_SERVICES):
            return f'{service.upper()} is disabled by the system and cannot be enabled at this time.'

        fields = config(**{'zone': zone, 'service': service, 'action': action})

        error = validate_management_access(fields)
        if (error):
            return error.message

        with IPTablesManager() as ipt:
            ipt.modify_management_access(fields)

            configure_management_access(fields)

        # blocking below code
        return None

    # start/stop/restart services parsing.
    valid_services: list = load_configuration('system').get_list('services')

    if ('restart_svc' in form):
        service = 'dnx-' + form.get('restart_svc', '').replace(' ', '-')
        action = 'restart'

    elif ('start_svc' in form):
        service = 'dnx-' + form.get('start_svc', '').replace(' ', '-')
        action = 'start'

    elif ('stop_svc' in form):
        service = 'dnx-' + form.get('stop_svc', '').replace(' ', '-')
        action = 'stop'

    else:
        return INVALID_FORM

    if (service not in valid_services):
        return INVALID_FORM

    system_action(module='webui', command=f'systemctl {action}', args=service)


# ==============
# VALIDATION
# ==============
SERVICE_TO_PORT: dict = {'webui': (80, 443), 'cli': (0,), 'ssh': (22,), 'ping': 1}

def validate_management_access(fields: config) -> Optional[ValidationError]:

    if (fields.zone not in ['lan', 'dmz'] or fields.service not in SERVICE_TO_PORT):
        raise ValidationError(INVALID_FORM)

    # convert_int will return -1  if issues with form data and ValueError will cover
    # invalid CFG action key/vals
    try:
        action = CFG(convert_int(fields.action))
    except ValueError:
        return ValidationError(INVALID_FORM)

    fields.action = action
    fields.service_ports = SERVICE_TO_PORT[fields.service]

# ==============
# CONFIGURATION
# ==============

def configure_management_access(fields: config):
    with ConfigurationManager('system') as dnx:
        mgmt_settings = dnx.load_configuration()

        mgmt_settings[f'mgmt_access->{fields.zone}->{fields.service}'] = fields.action

        dnx.write_configuration(mgmt_settings.expanded_user_data)
