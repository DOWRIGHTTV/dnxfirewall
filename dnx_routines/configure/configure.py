#!/usr/bin/python3

from __future__ import annotations

from dnx_gentools.file_operations import ConfigurationManager

__all__ = (
    'set_dns_servers'
)

# TODO: this needs to be redone.
def set_dns_servers(dns_server_info):
    field = {1: 'primary', 2: 'secondary'}

    with ConfigurationManager('dns_server') as dnx:
        dns_server_settings = dnx.load_configuration()

        public_resolvers = dns_server_settings['resolvers']

        for i, (server_name, ip_address) in enumerate(dns_server_info.items(), 1):
            if (not server_name or not ip_address):
                continue

            public_resolvers[field[i]].update({
                'name': server_name,
                'ip_address': ip_address
            })

        dnx.write_configuration(dns_server_settings)

# def set_syslog_settings(syslog_settings):
#     with ConfigurationManager('syslog_client') as dnx:
#         stored_syslog_settings = dnx.load_configuration()
#
#         syslog = stored_syslog_settings
#         tls_settings = syslog['tls']
#         tcp_settings = syslog['tcp']
#
#         for option in tls_settings:
#             if (option in syslog_settings['tls'] and option != 'retry'):
#                 tls_settings[option] = True
#
#             elif (option not in syslog_settings['tls']):
#                 tls_settings[option] = False
#
#         for protocol in ['tcp', 'udp']:
#             fallback = f'{protocol}_fallback'
#             if (fallback in syslog_settings['fallback']):
#                 syslog[protocol]['fallback'] = True
#             else:
#                 syslog[protocol]['fallback'] = False
#
#         syslog['protocol'] = 6 if 'syslog_protocol' in syslog_settings else 17
#         syslog['enabled'] = True if 'syslog_enabled' in syslog_settings else False
#
#         tls_settings['retry'] = int(syslog_settings['tls_retry']) * 60
#         tcp_settings['retry'] = int(syslog_settings['tcp_retry']) * 60
#
#         dnx.write_configuration(stored_syslog_settings)
#
# def set_syslog_servers(syslog_servers):
#     with ConfigurationManager('syslog_client') as dnx:
#         syslog_settings = dnx.load_configuration()
#
#         servers = syslog_settings['servers']
#         for server, server_info in syslog_servers.items():
#             if (not server_info['ip_address']): continue
#
#             servers.update({
#                 server: {
#                     'ip_address': server_info['ip_address'],
#                     'port': int(server_info['port'])
#                 }
#             })
#
#         dnx.write_configuration(syslog_settings)
#
# # NOTE: why is this returning a value? is this doing some validation checking?
# def remove_syslog_server(syslog_server_number):
#     with ConfigurationManager('syslog_client') as dnx:
#         syslog_settings = dnx.load_configuration()
#
#         servers = syslog_settings['servers']
#         result = servers.pop(f'Server{syslog_server_number}', False)
#         if (result and 'server2' in servers):
#             servers['server1'] = servers.pop('server2')
#
#         dnx.write_configuration(syslog_settings)
#
#     return result
