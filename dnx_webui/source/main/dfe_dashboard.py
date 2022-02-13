#!/usr/bin/python3

from itertools import zip_longest

from dnx_routines.configure.system_info import Interface, System, Services
from dnx_routines.database.ddb_connector_sqlite import DBConnector
from dnx_routines.logging.log_client import LogHandler as Log

def load_page():
    domain_counts, request_counts, top_domains, top_countries, inf_hosts = query_database()

    mod_status = {}
    for svc in ['dns-proxy', 'ip-proxy', 'ips', 'dhcp-server']:
        status = Services.status(f'dnx-{svc}')

        mod_status[svc.replace('-', '_')] = status

    dashboard = {
        'domain_counts': domain_counts, 'dc_graph': _calculate_graphic(domain_counts),
        'request_counts': request_counts, 'rc_graph': _calculate_graphic(request_counts),
        'top_domains': top_domains, 'top_countries': top_countries,
        'infected_hosts': inf_hosts,

        'interfaces': Interface.bandwidth(), 'uptime': System.uptime(), 'cpu': System.cpu_usage(),
        'ram': System.ram_usage(), 'dns_servers': System.dns_status(), 'module_status': mod_status
    }

    return dashboard

def query_database():
    domain_counts = (0, 0)
    request_counts = (0, 0)
    top_domains = (('blocked', ()), ('allowed', ()))
    top_countries = {'blocked': [], 'allowed': []}
    inf_hosts = []

    # TODO: implement executemany for back to back calls
    with DBConnector(Log) as firewall_db:
        domain_counts = (
            firewall_db.execute('unique_domain_count', action='blocked'),
            firewall_db.execute('unique_domain_count', action='allowed')
        )

        request_counts = (
            firewall_db.execute('total_request_count', table='dnsproxy', action='blocked'),
            firewall_db.execute('total_request_count', table='dnsproxy', action='allowed')
        )

        top_domains = (
            ('blocked', firewall_db.execute('top_dashboard', 5, action='blocked')),
            ('allowed', firewall_db.execute('top_dashboard', 5, action='allowed'))
        )

        top_countries = {}
        for action in ['blocked', 'allowed']:
            outbound = firewall_db.execute('top_geolocation', 5, action=action, direction='OUTBOUND')
            inbound = firewall_db.execute('top_geolocation', 5, action=action, direction='INBOUND')

            top_countries[action] = list(zip_longest(outbound, inbound, fillvalue=''))

        inf_hosts = firewall_db.execute('last', 5, table='infectedclients', action='all')

    return domain_counts, request_counts, top_domains, top_countries, inf_hosts

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
