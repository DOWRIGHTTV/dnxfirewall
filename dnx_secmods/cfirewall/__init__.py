#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_constants import hardout, INITIALIZE_MODULE

LOG_NAME = 'cfirewall'

if INITIALIZE_MODULE(LOG_NAME):
    import os

    from threading import Thread
    from dataclasses import dataclass

    from dnx_gentools.def_enums import Queue, QueueType

    from dnx_routines.logging.log_client import Log

    from fw_main import CFirewall, nl_open, nl_bind, nl_break, initialize_geolocation
    from fw_automate import FirewallAutomate


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

    try:
        args = Args(**{a: 1 for a in os.environ['PASSTHROUGH_ARGS'].split(',') if a})
    except Exception as E:
        hardout(f'DNXFIREWALL arg parse failure => {E}')

    Log.run(name=LOG_NAME)

def run():
    # ===============
    # NETLINK SOCKET
    # ===============
    nl_open()
    nl_bind()

    # ===============
    # GEOLOCATION
    # ===============
    # generating py_trie for geolocation signatures, cfirewall will initialize the extension natively
    geo_trie = generate_geolocation(Log)

    initialize_geolocation(geo_trie, MSB, LSB)

    # ===============
    # FIREWALL QUEUE
    # ===============
    dnxfirewall = CFirewall()

    # NOTE: bypass tells the process to invoke rule action (DROP or ACCEPT) without forwarding to security modules.
    dnxfirewall.set_options(args.bypass_set, args.verbose_set)

    error = dnxfirewall.nf_set(Queue.CFIREWALL, QueueType.FIREWALL)
    if (error):
        Log.error(f'failed to bind to queue {Queue.CFIREWALL}')
        hardout()

    # ===============
    # FIREWALL QUEUE
    # ===============
    dnxnat = CFirewall()
    dnxnat.set_options(0, args.verbose_set)

    error = dnxfirewall.nf_set(Queue.CNAT, QueueType.NAT)
    if (error):
        Log.error(f'failed to bind to queue {Queue.CNAT}')
        hardout()

    # initializing python processes for detecting configuration changes to zone or firewall rule sets and also handles
    # necessary calls into Cython via cfirewall reference for making the actual config change.
    # these will run in Python threads with a potential calling into Cython.
    # these functions should be explicitly identified since they will require the gil to be acquired on the Cython side
    # or else the Python interpreter will crash.
    fw_rule_monitor = FirewallAutomate(Log, cfirewall=dnxfirewall)
    try:
        fw_rule_monitor.run()
    except Exception as E:
        hardout(f'DNXFIREWALL control run failure => {E}')

    if (args.verbose_set):
        fw_rule_monitor.print_active_rules()

    # this is running in pure C. the GIL is released before running the low-level system operations and will never
    # retake the gil.
    dnx_threads = [
        Thread(target=dnxfirewall.nf_run),
        Thread(target=dnxnat.nf_run)
    ]
    for t in dnx_threads:
        t.start()

    try:
        for t in dnx_threads:
            t.join()
    except Exception as E:
        nl_break()
        hardout(f'DNXFIREWALL cfirewall/nfqueue failure => {E}')
