#!/usr/bin/python3

import os, sys

from types import SimpleNamespace

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-3]))
sys.path.insert(0, HOME_DIR)

import dnx_routines.configure.configure as configure
import dnx_routines.configure.web_validate as validate

from dnx_gentools.def_constants import INVALID_FORM
from dnx_routines.configure.exceptions import ValidationError
from dnx_gentools.file_operations import load_configuration
from dnx_routines.configure.system_info import Services
from dnx_system.sys_action import system_action
from dnx_routines.configure.iptables import IPTablesManager

DISABLED_MANAGEMENT_SERVICES = ['cli']

def load_page(form):
    dnx_settings = load_configuration('config')

    all_services = []
    for service, desc in dnx_settings['services'].items():
        status  = True if Services.status(service) else False
        service = ' '.join((service.split('-')[1:]))

        all_services.append((service, desc, status))

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

        fields = SimpleNamespace(**{'zone': zone, 'service': service, 'action': action})

        try:
            validate.management_access(fields)
        except ValidationError as ve:
            return ve

        else:
            with IPTablesManager() as ipt:
                ipt.modify_management_access(fields)

                configure.modify_management_access(fields)

            return

    # start/stop/restart services parsing.

    valid_services = load_configuration('config')['services']

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
