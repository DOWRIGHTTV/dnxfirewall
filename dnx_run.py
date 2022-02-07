#!/usr/bin/env python3

import os
import sys
import argparse
import importlib

parser = argparse.ArgumentParser(description='DNXFIREWALL utility to start an included module.')
parser.add_argument('module', metavar='mod', type=str)

print(sys.argv)

args = parser.parse_args(sys.argv[1:2])
print(args)

# =========================
# MOD NAME -> MOD LOCATION
# =========================
MODULE_MAPPING = {
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

valid_module = MODULE_MAPPING.get(args.module, False)
if (valid_module):
    os.environ['INIT_MODULE'] = 'YES'

    importlib.import_module(valid_module)
