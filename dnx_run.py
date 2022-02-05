#!/usr/bin/env python3

import sys
import argparse

parser = argparse.ArgumentParser(description='DNXFIREWALL utility to start an included module.')

parser.add_argument('module', metavar='mod', type=str)
parser.add_argument('-o', metavar='options', help='Arguments to passthrough to module', type=str)

args = parser.parse_args(sys.argv[1:])

# ========================
# GENERIC LIST OF MODULES
# ========================
RUN_MODULE = None

# SECURITY MODULES
if (args.module == 'cfirewall'):
    from dnx_secmods.cfirewall.fw_init import RUN_MODULE

elif (args.module == 'dns_proxy'):
    from dnx_secmods.dns_proxy.dns_proxy import RUN_MODULE

elif (args.module == 'ip_proxy'):
    from dnx_secmods.ip_proxy.ip_proxy import RUN_MODULE

elif (args.module == 'ips_ids'):
    from dnx_secmods.ips_ids.ips_ids import RUN_MODULE

# NETWORK MODULES
elif (args.module == 'dhcp_server'):
    from dnx_netmods.dhcp_server.dhcp_server import RUN_MODULE

# elif (args.module == 'syslog_client'):
#     from dnx_netmods.syslog_client.syl_main import RUN_MODULE

# ROUTINES
elif (args.module == 'database'):
    from dnx_routines.database.ddb_main import RUN_MODULE

elif (args.module == 'logging'):
    from dnx_routines.logging.log_main import RUN_MODULE

# SYSTEM
elif (args.module == 'startup'):
    from dnx_system.startup_proc import RUN_MODULE

elif (args.module == 'interface'):
    from dnx_system.interface_services import RUN_MODULE

elif (args.module == 'syscontrol'):
    from dnx_system.sys_control import RUN_MODULE

# USER INTERFACE
# elif (args.module == 'webui'):
#     from dnx_webui.source.main.dfe_main import app as application
#
#     RUN_MODULE = application.run

if (RUN_MODULE):
    RUN_MODULE()
