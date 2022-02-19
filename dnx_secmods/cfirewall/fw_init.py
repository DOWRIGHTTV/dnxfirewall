#!/usr/bin/env python3

from __future__ import annotations

import sys
import argparse

from dnx_gentools.def_constants import hard_out, INIT_MODULE
from dnx_gentools.def_enums import Queue

from dnx_routines.logging.log_client import LogHandler as Log

from dnx_secmods.cfirewall.fw_main import CFirewall
from dnx_secmods.cfirewall.fw_control import FirewallControl

if (INIT_MODULE):

    parser = argparse.ArgumentParser()
    parser.add_argument('--bypass', action='store_true')
    parser.add_argument('--verbose', action='store_true')

    args = parser.parse_args(sys.argv)

    Log.run(name='rules')

    dnxfirewall = CFirewall()
    dnxfirewall.set_options(args.bypass, args.verbose)

    error = dnxfirewall.nf_set(Queue.CFIREWALL)
    if (error):
        Log.error(f'failed to bind to queue {Queue.CFIREWALL}')
        hardout()

    # initializing python processes for detecting configuration changes to zone or rules rule sets and also handles
    # necessary calls into Cython via cfirewall reference for making the actual config change. these will run in Python
    # threads and some may call into Cython. These functions should be explicitly identified since they will require the
    # gil to be acquired on the Cython side or else the Python interpreter will crash.
    fw_control = FirewallControl(Log, cfirewall=dnxfirewall)
    try:
        fw_control.run()
    except:
        hardout()

    # this is a blocking call but is running in pure C. the GIL is released before running the low level system
    # operations and will never retake the gil.
    # NOTE: setting bypass will tell the process to invoke rules action (DROP or ACCEPT) directly without
    #  forwarding to other modules.
    try:
        dnxfirewall.nf_run()
    except:
        dnxfirewall.nf_break()
        hardout()
