#!/usr/bin/env python3

import os, sys

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-2]))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import Queue
from dnx_sysmods.logging.log_main import LogHandler as Log

from dnx_secmods.cfirewall.fw_main import CFirewall # pylint: disable=import-error, no-name-in-module
from dnx_secmods.cfirewall.fw_control import FirewallControl

LOG_NAME = 'firewall'

Log.run(
    name=LOG_NAME
)

dnxfirewall = CFirewall()
error = dnxfirewall.nf_set(Queue.CFIREWALL)
if (error):
    Log.error(f'failed to bind to queue {Queue.CFIREWALL}')
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
