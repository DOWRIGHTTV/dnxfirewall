#!/usr/bin/python3

import json
import sys, os

from flask import Flask, render_template, redirect, url_for, request, session

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import INVALID_FORM
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_iptables import IPTableManager
from dnx_configure.dnx_system_info import System, Services

def load_page():
    fw_rules = System.firewall_rules()
    nat_rules = System.nat_rules()

    netmasks = list(reversed(range(24,33)))

    firewall_settings = {'firewall_rules': fw_rules, 'nat_rules': nat_rules, 'netmasks': netmasks}

    return firewall_settings

# TODO: fix inconcistent variable names for nat rules
def update_page(form):
    if ('fw_remove' in form):
        fw_rule = form.get('fw_remove', None)
        chain = 'FIREWALL'
        if (not fw_rule):
            return INVALID_FORM

        try:
            validate.del_firewall_rule(fw_rule, chain)
        except ValidationError as ve:
            return ve
        else:
            with IPTableManager() as iptables:
                iptables.delete_rule(fw_rule, chain='FIREWALL')

    elif ('fw_add' in form):
        pos = form.get('position', None)
        dst_ip = form.get('dst_ip', None)
        dst_netmask = form.get('dst_netmask', None)
        src_ip = form.get('src_ip', None)
        src_netmask = form.get('src_netmask', None)
        protocol = form.get('protocol', None)
        dst_port = form.get('dst_port', False)
        if (dst_port == ''):
            dst_port = None

        if (src_ip == ''):
            src_ip = '0'
            src_netmask = '0'

        if ('accept' in form):
            action = 'ACCEPT'
        else:
            action = 'DROP'

        iptable_rule = {
            'pos': pos, 'src_ip': src_ip, 'src_netmask': src_netmask, 'dst_ip': dst_ip,
            'dst_netmask': dst_netmask, 'dst_port': dst_port, 'protocol': protocol,
            'action': action
        }
        # TODO: make this less compiticated?
        if (pos and dst_ip and dst_netmask and src_ip and
                src_netmask and protocol and dst_port is not False):
            try:
                validate.add_firewall_rule(iptable_rule)
                if (dst_port != None):
                    validate.network_port(dst_port)
                if (src_ip != '0'):
                    validate.ip_address(src_ip)
                    validate.cidr(src_netmask)
                validate.cidr(dst_netmask)
                validate.ip_address(dst_ip)

                with IPTableManager() as iptables:
                    iptables.add_rule(iptable_rule)

            except ValidationError as ve:
                return ve
        else:
            return INVALID_FORM

    elif ('nat_remove' in form):
        nat_rule = form.get('nat_remove', None)
        if (not nat_rule):
            return INVALID_FORM

        try:
            validate.del_firewall_rule(nat_rule, chain='NAT')
        except ValidationError as ve:
            return ve
        else:
            configure.del_open_wan_protocol(nat_rule)
            with IPTableManager() as iptables:
                iptables.delete_nat(nat_rule)

    elif ('nat_add' in form):
        host_ip  = form.get('host_ip', None)
        protocol = form.get('protocol', None)
        if (protocol in ['tcp', 'udp']):
            dst_port  = form.get('dst_port')
            host_port = form.get('host_port')

        elif (protocol in ['icmp']):
            dst_port  = None
            host_port = None

            open_protocols = load_configuration('ips.json')
            icmp_allow = open_protocols['ips']['open_protocols']['icmp']
            if (icmp_allow):
                return 'Only one ICMP rule can be active at a time. Remove existing rule before adding another.'
        else:
            return INVALID_FORM

        try:
            if (protocol in ['tcp', 'udp']):
                validate.network_port(dst_port)
                validate.network_port(host_port)
            validate.ip_address(host_ip)
        except ValidationError as ve:
            return ve
        else:
            with IPTableManager() as iptables:
                iptables.add_nat(protocol, dst_port, host_ip, host_port)

            configure.add_open_wan_protocol(protocol, dst_port, host_port)
    else:
        return INVALID_FORM
