#!/usr/bin/env python3

from __future__ import annotations

from typing import Optional

import os
import sys
import time
import argparse
import importlib

from functools import partial
from subprocess import check_call, DEVNULL, CalledProcessError

hardout = os._exit

parser = argparse.ArgumentParser(description='DNXFIREWALL utility to start an included module.')
parser.add_argument('module', metavar='mod', type=str)
parser.add_argument('-s', metavar='service', type=str, choices=['start', 'stop', 'restart'], default='')

# exceptions will handle different ways to call file. args will be sliced just before passthrough args begin.
try:
    args = parser.parse_args(sys.argv[1:4])

    sys.argv = sys.argv[4:]
except:
    try:
        args = parser.parse_args(sys.argv[1:3])

        sys.argv = sys.argv[3:]
    except:
        args = parser.parse_args(sys.argv[1:2])

        sys.argv = sys.argv[2:]

dnx_run = partial(check_call, stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL)

# =========================
# MOD NAME -> MOD LOCATION
# =========================
MODULE_MAPPING: dict[str, str] = {
    # INFORMATIONAL
    'modstat': 'modstat',

    # SECURITY MODULES
    'cfirewall': 'dnx_secmods.cfirewall.fw_init',
    'dns_proxy': 'dnx_secmods.dns_proxy.dns_proxy',
    'ip_proxy': 'dnx_secmods.ip_proxy.ip_proxy',
    'ips_ids': 'dnx_secmods.ips_ids.ips_ids',

    # NETWORK MODULES
    'dhcp_server': 'dnx_netmods.dhcp_server.dhcp_server',

    # ROUTINES
    'database': 'dnx_routines.database.ddb_main',
    'logging': 'dnx_routines.logging.log_main',

    # SYSTEM
    'startup': 'dnx_system.startup_proc',
    'interface': 'dnx_system.interface_services',
    'syscontrol': 'dnx_system.sys_control'
}

systemctl_ret_codes: dict[int,str] = {
    0: 'program is running or service is OK',
    1: 'program dead and /var/run pid file exists',
    2: 'program dead and /var/lock lock file exists',
    3: 'program not running',
    4: 'program service status is unknown',
}

def check_priv(command: str) -> None:
    if os.getuid():
        exit(f'\nDNXFIREWALL {command} command requires root.\n')


valid_module = MODULE_MAPPING.get(args.module, False)
if (not valid_module):
    exit('\nUNKNOWN COMMAND -> see --help\n')

if (valid_module == 'modstat'):
    check_priv('modstat')

    svc_len: int = 0
    down_detected: bool = False

    status: list[Optional[list[str, str]]] = []
    for mod in list(MODULE_MAPPING)[1:]:
        service = f'dnx-{mod.replace("_", "-")}'

        svc_len = len(service) if len(service) > svc_len else svc_len

        try:
            dnx_run(f'sudo systemctl status {service}', shell=True)
        except CalledProcessError as E:
            status.append([service, f'down  code={E.returncode}  msg="{systemctl_ret_codes.get(E.returncode, "")}"'])

            down_detected = True

        else:
            status.append([service, 'up'])

    # =================================
    # OUTPUT - Justified left<==>right
    # =================================
    # dnx-cfirewall   => down (code=4)
    print('# =====================')
    print('# DNXFIREWALL SERVICES')
    print('# =====================')
    for svc, result in status:
        time.sleep(0.05)
        print(f'{svc.ljust(svc_len)} => {result.rjust(4)}')

    if (down_detected):
        print(f'\ndowned service detected. check journal for more details.')

elif (args.s):
    check_priv('service')
    try:
        dnx_run(['systemctl', valid_module, args.s])
    except CalledProcessError:
        print(f'{valid_module} service {args.s} failed. check journal.')

    else:
        print(f'{valid_module} service {args.s} successful.')

else:
    os.environ['INIT_MODULE'] = 'YES'

    try:
        importlib.import_module(valid_module)
    except Exception as E:
        print(f'{valid_module} cli run failure. => {E}')
        hardout(0)
