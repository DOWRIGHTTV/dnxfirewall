#!/usr/bin/python3

import json
import sys, os, time

from itertools import zip_longest

from dnx_sysmods.configure.file_operations import load_configuration
from dnx_sysmods.configure.system_info import Interface, System, Services
from dnx_sysmods.database.ddb_connector_sqlite import DBConnector

def load_page():
    with DBConnector() as ProxyDB:
        domain_counts = (
            ProxyDB.unique_domain_count(action='blocked'),
            ProxyDB.unique_domain_count(action='allowed')
        )

        request_counts = (
            ProxyDB.total_request_count(table='dnsproxy', action='blocked'),
            ProxyDB.total_request_count(table='dnsproxy', action='allowed')
        )

        top_domains = (
            ('blocked', ProxyDB.dashboard_query_top(5, action='blocked')),
            ('allowed', ProxyDB.dashboard_query_top(5, action='allowed'))
        )

        top_countries = {}
        for action in ['blocked', 'allowed']:
            outbound = ProxyDB.query_geolocation(5, action=action, direction='OUTBOUND')
            inbound = ProxyDB.query_geolocation(5, action=action, direction='INBOUND')

            top_countries[action] = list(zip_longest(outbound, inbound, fillvalue=''))

        inf_hosts = ProxyDB.query_last(5, table='infectedclients', action='all')

    intstat = Interface.bandwidth()

    uptime = System.uptime()
    cpu = System.cpu_usage()
    ram = System.ram_usage()
    dns_servers = System.dns_status()

    mod_status = {}
    for svc in ['dns-proxy', 'ip-proxy', 'ips', 'dhcp-server']:
        status = Services.status(f'dnx-{svc}')

        mod_status[svc.replace('-', '_')] = status

    dashboard = {
        'domain_counts': domain_counts, 'dc_graph': _calculate_graphic(domain_counts),
        'request_counts': request_counts, 'rc_graph': _calculate_graphic(request_counts),
        'top_domains': top_domains, 'top_countries': top_countries,
        'infected_hosts': inf_hosts,

        'interfaces': intstat, 'uptime': uptime, 'cpu': cpu,
        'ram': ram, 'dns_servers': dns_servers, 'module_status': mod_status
    }

    return dashboard

def _calculate_graphic(counts):
    # bigger, smaller
    graphic = ['u', 'u']

    # indexes for easier conditionals
    bigger, smaller = 0, 1

    blocked, allowed = counts

    # block majority
    if (blocked > allowed):
        graphic[bigger] = 'b'

        if (allowed):
            graphic[smaller] = 'a'

    # allow majority
    elif (allowed > blocked):
        graphic[bigger] = 'a'

        if (blocked):
            graphic[smaller] = 'b'

    return graphic
