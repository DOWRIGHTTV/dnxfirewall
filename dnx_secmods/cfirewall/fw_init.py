#!/usr/bin/env python3

from __future__ import annotations

import os

from threading import Thread
from dataclasses import dataclass

from dnx_gentools.def_constants import hardout, INIT_MODULE
from dnx_gentools.def_enums import Queue

from dnx_routines.logging.log_client import Log

from fw_main import CFirewall
from fw_control import FirewallControl

LOG_NAME = 'cfirewall'

@dataclass
class Args:
    b: int = 0
    v: int = 0
    bypass: int = 0
    verbose: int = 0

    @property
    def bypass_set(self):
        return self.b or self.bypass

    @property
    def verbose_set(self):
        return self.v or self.verbose

def run():

    dnxfirewall: CFirewall = CFirewall()
    dnxfirewall.set_options(args.bypass_set, args.verbose_set)

    error = dnxfirewall.nf_set(Queue.CFIREWALL)
    if (error):
        Log.error(f'failed to bind to queue {Queue.CFIREWALL}')
        hardout()

    # initializing python processes for detecting configuration changes to zone or firewall rule sets and also handles
    # necessary calls into Cython via cfirewall reference for making the actual config change.
    # these will run in Python threads with a potential calling into Cython.
    # these functions should be explicitly identified since they will require the gil to be acquired on the Cython side
    # or else the Python interpreter will crash.
    fw_control: FirewallControl = FirewallControl(Log, cfirewall=dnxfirewall)
    try:
        fw_control.run()
    except Exception as E:
        hardout(f'DNXFIREWALL control run failure => {E}')

    # this is running in pure C. the GIL is released before running the low level system operations and will never
    # retake the gil.
    # NOTE: setting bypass will tell the process to invoke rule action (DROP or ACCEPT) directly without forwarding to
    #  other modules.
    dnx: Thread = Thread(target=dnxfirewall.nf_run)
    dnx.start()
    try:
        dnx.join()
    except Exception as E:
        dnxfirewall.nf_break()
        hardout(f'DNXFIREWALL cfirewall/nfqueue failure => {E}')


if (INIT_MODULE == LOG_NAME):
    args = Args(**{a: 1 for a in os.environ['PASSTHROUGH_ARGS'].split(',')})

    Log.run(name=LOG_NAME)
