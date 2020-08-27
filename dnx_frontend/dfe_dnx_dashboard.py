#!/usr/bin/python3

import json
import sys, os, time

from flask import Flask, render_template, redirect, url_for, request, session

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_system_info import Interface, System, Services
from dnx_database.ddb_connector_sqlite import DBConnector

def load_page():
    with DBConnector() as ProxyDB:
        domain_count = ProxyDB.unique_domain_count(table='dnsproxy', action='blocked')
        top_domains = ProxyDB.dashboard_query_top(5, table='dnsproxy', action='blocked')
        request_count = ProxyDB.total_request_count(table='dnsproxy', action='blocked')
        inf_hosts = ProxyDB.query_last(5, table='infectedclients', action='all')

    Int = Interface()
    intstat = Int.bandwidth()

    uptime = System.uptime()
    cpu = System.cpu_usage()
    ram = System.ram_usage()
    dns_servers = System.dns_status()

    #----- Services Status ------#
    dns_proxy = Services.status('dnx-dns-proxy')
    ip_proxy = Services.status('dnx-ip-proxy')
    dhcp_server = Services.status('dnx-dhcp-server')
    dnx_ips = Services.status('dnx-ips')

    mod_status = {
        'dns_proxy': dns_proxy, 'ip_proxy': ip_proxy, 'dnx_ips': dnx_ips, 'dhcp_server': dhcp_server
    }

    dnx_license = load_configuration('license')['license']
    updates = load_configuration('updates')['updates']

    notify = False
    if (dnx_license['validated']):
        system_uptodate = updates['system']['current']
        domains_uptodate = updates['signature']['domain']['current']
        ip_uptodate = updates['signature']['ip']['current']

        if not all([system_uptodate, domains_uptodate, ip_uptodate]):
            notify = 'DNX firewall has updates available. Check updates tab for more info.'

    # System/Service Restart pending check
    sys_restart = updates['system']['restart']
    domain_restart = updates['signature']['domain']['restart']
    ip_restart = updates['signature']['ip']['restart']

    if (domain_restart or ip_restart):
        notify = 'One or more DNX Services require a restart after signature updates. Please check the updates page for more information.'

    if (sys_restart):
        notify = 'DNX firewall is pending a system restart after updates.'

    dashboard = {
        'domain_count': domain_count, 'infected_hosts': inf_hosts, 'top_domains': top_domains,
        'request_count': request_count, 'interfaces': intstat, 'uptime': uptime, 'cpu': cpu,
        'ram': ram, 'dns_servers': dns_servers, 'module_status': mod_status, 'notify': notify
    }

    return dashboard
