#!/usr/bin/python3

import os, sys

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure

from dnx_configure.dnx_constants import INVALID_FORM
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_system_info import Services

def load_page():
    system_services = load_configuration('config')['services']

    all_services = []
    for service, desc in system_services.items():
        status  = True if Services.status(service) else False
        service = ' '.join((service.split('-')[1:]))

        all_services.append((service, desc, status))

    return all_services

def update_page(form):
    valid_services = load_configuration('config')['services']
    sec_flags = {'dnx-ip-proxy': 'ip', 'dnx-dns-proxy': 'domain'}

    if ('restart_svc' in form):
        service = form.get('restart_svc')

        service = 'dnx-' + service.replace(' ', '-')
        if (service not in valid_services):
            return INVALID_FORM

        Services.restart(service)

        if (service in sec_flags):
            ruleset = sec_flags[service]
            configure.reset_module_flags(system=False, signatures=True, ruleset=ruleset)

    elif ('start_svc' in form):
        service = form.get('start_svc')

        service = 'dnx-' + service.replace(' ', '-')
        if (service not in valid_services):
            return INVALID_FORM

        Services.start(service)

    elif ('stop_svc' in form):
        service = form.get('stop_svc')

        service = 'dnx-' + service.replace(' ', '-')
        if (service not in valid_services):
            return INVALID_FORM

        Services.stop(service)

        if (service in sec_flags):
            ruleset = sec_flags[service]
            configure.reset_module_flags(system=False, signatures=True, ruleset=ruleset)
    else:
        return INVALID_FORM
