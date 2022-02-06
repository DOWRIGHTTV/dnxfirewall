#!/usr/bin/env python3

from dnx_gentools.def_constants import hard_out, Queue

from dnx_routines.logging.log_client import LogHandler as Log

from dnx_secmods.cfirewall.fw_main import CFirewall
from dnx_secmods.cfirewall.fw_control import FirewallControl

def RUN_MODULE(bypass: bool = False, verbose: bool = False):

    Log.run(name='firewall')

    dnxfirewall = CFirewall(bypass, verbose)
    error = dnxfirewall.nf_set(Queue.CFIREWALL)
    if (error):
        Log.error(f'failed to bind to queue {Queue.CFIREWALL}')
        hard_out()

    # initializing python processes for detecting configuration changes to zone or firewall rule sets and also handles
    # necessary calls into Cython via cfirewall reference for making the actual config change. these will run in Python
    # threads and some may call into Cython. These functions should be explicitly identified since they will require the
    # gil to be acquired on the Cython side or else the Python interpreter will crash.
    fw_control = FirewallControl(Log, cfirewall=dnxfirewall)
    try:
        fw_control.run()
    except:
        hard_out()

    # this is a blocking call but is running in pure C. the GIL is released before running the low level system
    # operations and will never retake the gil. NOTE: setting bypass will tell the process to invoke firewall action
    # (DROP or ACCEPT) directly without forwarding to other modules.
    try:
        dnxfirewall.nf_run()
    except:
        dnxfirewall.nf_break()
        hard_out()
