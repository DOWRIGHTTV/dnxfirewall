#!/usr/bin/python3

from typing import Optional

import dnx_routines.configure.configure as configure

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.def_enums import CFG
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config

from dnx_routines.configure.web_validate import convert_int, ValidationError
from dnx_routines.configure.system_info import Services
from dnx_routines.configure.iptables import IPTablesManager

from dnx_system.sys_action import system_action

DISABLED_MANAGEMENT_SERVICES = ['cli']

def load_page(form):
    dnx_settings = load_configuration('system')

    all_services = []
    for service, desc in dnx_settings.get_items('services'):
        service = ' '.join((service.split('-')[1:]))

        all_services.append((service, desc, Services.status(service)))

    return {'all_services': all_services, 'mgmt_access': dnx_settings['mgmt_access']}

def update_page(form):

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

        return

    # start/stop/restart services parsing.

    valid_services = load_configuration('system')['services']

    if ('restart_svc' in form):
        service = form.get('restart_svc')

        service = 'dnx-' + service.replace(' ', '-')
        if (service not in valid_services):
            return INVALID_FORM

        system_action(module='webui', command='systemctl restart', args=service)

        Services.restart(service)

    elif ('start_svc' in form):
        service = form.get('start_svc')

        service = 'dnx-' + service.replace(' ', '-')
        if (service not in valid_services):
            return INVALID_FORM

        system_action(module='webui', command='systemctl start', args=service)

    elif ('stop_svc' in form):
        service = form.get('stop_svc')

        service = 'dnx-' + service.replace(' ', '-')
        if (service not in valid_services):
            return INVALID_FORM

        system_action(module='webui', command='systemctl stop', args=service)

    else:
        return INVALID_FORM


# ==============
# VALIDATION
# ==============
SERVICE_TO_PORT = {'webui': (80, 443), 'cli': (0,), 'ssh': (22,), 'ping': 1}

def validate_management_access(fields: config) -> Optional[ValidationError]:

    if (fields.zone not in ['lan', 'dmz'] or fields.service not in ['webui', 'cli', 'ssh', 'ping']):
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
