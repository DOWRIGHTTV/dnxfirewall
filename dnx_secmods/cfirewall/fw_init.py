#!/usr/bin/env python3

import __init__ # pylint: disable=import-error

import argparse

from sys import argv

from dnx_gentools.def_constants import hard_out, Queue

from dnx_routines.logging.log_main import log_handler as Log

from dnx_secmods.cfirewall.fw_main import CFirewall # pylint: disable=import-error, no-name-in-module
from dnx_secmods.cfirewall.fw_control import FirewallControl

parser = argparse.ArgumentParser(description='DNXFIREWALL/CFirewall command line executor')
parser.add_argument('--bypass', help='sets cfirewall to bypass security modules', action='store_true')
parser.add_argument('--verbose', help='prints informational messages', action='store_true')

args = parser.parse_args(argv[1:])

Log.run(name='firewall')

dnxfirewall = CFirewall(args.bypass, args.verbose)
error = dnxfirewall.nf_set(Queue.CFIREWALL)
if (error):
    Log.error(f'failed to bind to queue {Queue.CFIREWALL}')
    hard_out()

# initializing python processes for detecting configuration changes to zone or firewall rulesets and also handles
# necessary calls into Cython via cfirewall reference for making the actual config change. these will run in Python
# threads and some may call into Cython. These functions should be explicitly identified since they will require the gil
# to be acquired on the Cython side or else the Python interpreter will crash.
fw_control = FirewallControl(Log, cfirewall=dnxfirewall)
try:
    fw_control.run()
except:
    hard_out()

# this is a blocking call but is ran in pure C, releases the GIL before running the low level system operations, and
# will never retake the gil. NOTE: setting bypass will tell the process to invoke firewall action (DROP or ACCEPT)
# directly without forwarding to other modules.
try:
    dnxfirewall.nf_run()
except:
    dnxfirewall.nf_break()
    hard_out()
