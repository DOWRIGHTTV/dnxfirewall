#!/usr/bin/env python3

import __init__

import os
import argparse

from sys import argv

from dnx_sysmods.configure.def_constants import Queue
from dnx_sysmods.logging.log_main import LogHandler as Log

from dnx_secmods.cfirewall.fw_main import CFirewall # pylint: disable=import-error, no-name-in-module
from dnx_secmods.cfirewall.fw_control import FirewallControl

parser = argparse.ArgumentParser(description='DNXFIREWALL/CFirewall command line executor')
parser.add_argument('--bypass', help='sets cfirewall to bypass security modules', action='store_true')
parser.add_argument('--verbose', help='prints informational messages', action='store_true')

args = parser.parse_args(argv[1:])

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
# identified since they will require the gil to be acquired on the Cython side or else the Python interpreter
# will crash.
fw_control = FirewallControl(cfirewall=dnxfirewall)
fw_control.run()

# this is a blocking call but is ran in pure C. This call releases the GIL before running the low level
# system operations and will never retake the gil. #NOTE: setting bypass will tell the process to invoke
# firewall action(DROP or ACCEPT) directly without forwarding to other modules.
try:
    dnxfirewall.nf_run(args.bypass, args.verbose)
except:
    dnxfirewall.nf_break()
    os._exit(1)
