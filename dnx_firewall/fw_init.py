#!/usr/bin/env python3

import os, sys

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_firewall.fw_main import Firewall # pylint: disable=import-error, no-name-in-module
from dnx_firewall.fw_control import FirewallControl
from dnx_logging.log_main import LogHandler as Log

INITIAL_QUEUE = 69
LOG_NAME = 'firewall'

Log.run(
    name=LOG_NAME
)

dnxfirewall = Firewall()
error = dnxfirewall.nf_set(INITIAL_QUEUE)

# starting thread to send/ receive control messages to from other system services
if (not error):
    fw_control = FirewallControl(firewall=dnxfirewall)
    fw_control.run()

else:
    print(f'error binding to queue {INITIAL_QUEUE}')

# this is a blocking call but is ran in pure C. this call will never hold the gil.
dnxfirewall.nf_run()
