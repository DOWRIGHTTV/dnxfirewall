#!/usr/bin/python3

from __future__ import annotations

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_constants import space_join
from dnx_gentools.def_enums import CFG
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config
from dnx_gentools.system_info import Services

from dnx_control.control.ctl_action import system_action

from dnx_secmods.cfirewall.fw_control import FirewallControl

from source.web_interfaces import StandardWebPage

__all__ = ('WebPage',)

DISABLED_MANAGEMENT_SERVICES = ['cli', 'ping']

class WebPage(StandardWebPage):
    '''
    available methods: load, handle_ajax
    '''
    @staticmethod
    def load(_: Form) -> dict[str, Any]:
        dnx_settings: ConfigChain = load_configuration('system', cfg_type='global')

        all_services = []
        for service, desc in dnx_settings.get_items('services'):
            service_name = space_join((service.split('-')[1:]))

            all_services.append((service_name, desc, Services.status(service)))

        return {'all_services': all_services, 'mgmt_access': dnx_settings.get_dict('mgmt_access')}

    @staticmethod
    def update(form: Form) -> tuple[int, str]:

        # checking if button keys are present in form is easy first line validation to ensure valid form fields
        if ('update_mgmt_access' in form):

            try:
                zone, service, action = form.get('update_mgmt_access').split(',')
            except:
                return 1, INVALID_FORM

            if (service in DISABLED_MANAGEMENT_SERVICES):
                return 98, f'{service.upper()} is disabled by the system and cannot be enabled at this time.'

            fields = config(**{'name': zone, 'service': service, 'action': action})

            if error := validate_management_access(fields):
                return 2, error.message

            if FirewallControl.modify_management_access(fields):
                configure_management_access(fields)

            # blocking below code
            return NO_STANDARD_ERROR

        # start/stop/restart services parsing.
        valid_services: list = load_configuration('system', cfg_type='global').get_list('services')

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
            return 99, INVALID_FORM

        if (service not in valid_services):
            return 3, INVALID_FORM

        system_action(module='webui', command=f'systemctl {action}', args=service)

        return NO_STANDARD_ERROR


# ==============
# VALIDATION
# ==============
SERVICE_TO_PORT = {'webui': (80, 443), 'cli': (0,), 'ssh': (22,), 'ping': 1}
ZONE_TO_INT = {'lan': 11, 'dmz': 12}

def validate_management_access(fields: config) -> Optional[ValidationError]:

    if (fields.name not in ['lan', 'dmz'] or fields.service not in SERVICE_TO_PORT):
        raise ValidationError(INVALID_FORM)

    # convert_int will return -1 if issues with form data and ValueError will cover invalid CFG action key/vals
    try:
        action = CFG(convert_int(fields.action))
    except ValueError:
        return ValidationError(INVALID_FORM)

    else:
        if action not in [CFG.DEL, CFG.ADD]:
            return ValidationError(INVALID_FORM)

    fields.zone = ZONE_TO_INT[fields.name]
    fields.action = action
    fields.service_ports = SERVICE_TO_PORT[fields.service]

# ==============
# CONFIGURATION
# ==============
def configure_management_access(fields: config):
    with ConfigurationManager('system', cfg_type='global') as dnx:
        mgmt_settings = dnx.load_configuration()

        mgmt_settings[f'mgmt_access->{fields.name}->{fields.service}'] = fields.action - 1 # enum offset

        dnx.write_configuration(mgmt_settings.expanded_user_data)
