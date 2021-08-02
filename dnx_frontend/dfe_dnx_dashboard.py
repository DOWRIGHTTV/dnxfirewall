#!/usr/bin/python3

import json
import sys, os, time

from itertools import zip_longest
from flask import Flask, render_template, redirect, url_for, request, session

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_system_info import Interface, System, Services
from dnx_database.ddb_connector_sqlite import DBConnector

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
            outbound = ProxyDB.query_geolocation(5, action=action, direction='outbound')
            inbound = ProxyDB.query_geolocation(5, action=action, direction='inbound')

            top_countries[action] = list(zip_longest(outbound, inbound, fillvalue=''))

        inf_hosts = ProxyDB.query_last(5, table='infectedclients', action='all')

    print(top_countries)
    # TODO: see if this is a candidate for a class method
    Int = Interface()
    intstat = Int.bandwidth()

    uptime = System.uptime()
    cpu = System.cpu_usage()
    ram = System.ram_usage()
    dns_servers = System.dns_status()

    # TODO: make this iterable
    dns_proxy = Services.status('dnx-dns-proxy')
    ip_proxy = Services.status('dnx-ip-proxy')
    dhcp_server = Services.status('dnx-dhcp-server')
    dnx_ips = Services.status('dnx-ips')

    mod_status = {
        'dns_proxy': dns_proxy, 'ip_proxy': ip_proxy, 'dnx_ips': dnx_ips, 'dhcp_server': dhcp_server
    }

    dashboard = {
        'domain_counts': domain_counts, 'request_counts': request_counts,
        'top_domains': top_domains, 'top_countries': top_countries,
        'infected_hosts': inf_hosts,

        'interfaces': intstat, 'uptime': uptime, 'cpu': cpu,
        'ram': ram, 'dns_servers': dns_servers, 'module_status': mod_status
    }

    return dashboard
