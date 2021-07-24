#!/usr/bin/python3

import os, sys

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure

from dnx_configure.dnx_constants import INVALID_FORM
from dnx_configure.dnx_validate import convert_int
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_system_info import Services

def load_page():
    system_services = load_configuration('config')['services']

    mgmt_access = load_configuration('config')['settings']['mgmt_access']

    all_services = []
    for service, desc in system_services.items():
        status  = True if Services.status(service) else False
        service = ' '.join((service.split('-')[1:]))

        all_services.append((service, desc, status))

    return {'all_services': all_services, 'mgmt_access': mgmt_access}

def update_page(form):
    print(form)
    # checking if present in form is easy first line validation to ensure form
    # has the keys it should.
    if ('update_mgmt_access' in form):

        try:
            zone, service, action = form.get('update_mgmt_access').split(',')

        except:
            return INVALID_FORM

        else:
            action = convert_int(action)

            # TODO: write back end code to update file and add/remove iptables rules as needed.

            return

    # start/stop/restart services parsing.

    valid_services = load_configuration('config')['services']

    if ('restart_svc' in form):
        service = form.get('restart_svc')

        service = 'dnx-' + service.replace(' ', '-')
        if (service not in valid_services):
            return INVALID_FORM

        Services.restart(service)

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

    else:
        return INVALID_FORM
