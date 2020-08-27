#!/usr/bin/env python3

import os, sys
import time
import uuid
import json

_HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, _HOME_DIR)

from dnx_configure.dnx_constants import ONE_DAY, fast_time
from dnx_configure.dnx_file_operations import load_configuration, ConfigurationManager
from dnx_iptools.dnx_interface import get_mac
from dnx_logging.log_main import LogHandler as Log

__all__ = (
    'License'
)


class License:
    def __init__(self):
        dnx_settings = load_configuration('config')['settings']

        lan_int = dnx_settings['interfaces']['lan']['ident']

        self.mac = get_mac(interface=lan_int)

    def get_uuid(self, user_uuid):
        system_uuid = str(uuid.uuid3(uuid.NAMESPACE_URL, self.mac))

        if (user_uuid == system_uuid): return True

        return False

    def set_uuid(self, user_uuid):
        if not self.get_uuid(user_uuid): return

        with ConfigurationManager('license') as dnx:
            system_license = dnx.load_configuration()

            dnx_license = system_license['license']
            dnx_license.update({
                'mac': self.mac,
                'uuid': user_uuid,
                'activated': True
            })

            dnx.write_configuration(system_license)

    @staticmethod
    def timeout_status():
        with ConfigurationManager('license') as dnx:
            dnx_license = dnx.load_configuration()['license']

            if not dnx_license['activated']: return

            timestamp = dnx_license['timestamp']
            if (fast_time() - timestamp >= ONE_DAY and dnx_license['validated']):

                dnx_license['validated'] = False

                dnx.write_configuration(dnx_license)

                Log.warning('DNX license has been invalidated because it has not contacted the license server in 24 hours.')
