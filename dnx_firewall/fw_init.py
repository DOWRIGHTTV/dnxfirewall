#!/usr/bin/env python3

import os, sys

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_firewall.fw_main import CFirewall # pylint: disable=import-error, no-name-in-module
from dnx_firewall.fw_control import FirewallControl
from dnx_logging.log_main import LogHandler as Log

INITIAL_QUEUE = 69
LOG_NAME = 'firewall'

Log.run(
    name=LOG_NAME
)

dnxfirewall = CFirewall()
error = dnxfirewall.nf_set(INITIAL_QUEUE)
if (error):
    print(f'error binding to queue {INITIAL_QUEUE}')
    os._exit(1)

# initializing python processes for detecting configuration changes to zone or firewall rulesets and
# also handles necessary calls into Cython via cfirewall reference for making the actual config change.
# these will run in Python threads and some may call into Cython. These functions should be explicitly
# identified since they will require the gil to be aquired on the Cython side or else the Python interpreter
# will crash.
fw_control = FirewallControl(cfirewall=dnxfirewall)
fw_control.run()

# this is a blocking call but is ran in pure C. This call releases the GIL before running the low level
# system operations and will never retake the gil. #NOTE: setting bypass will tell the process to invoke
# firewall action(DROP or ACCEPT) directly without forwarding to other modules.
try:
    dnxfirewall.nf_run(bypass=1)
except:
    os._exit(1)
