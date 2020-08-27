#!/usr/bin/python3

import json
import sys, os

from flask import Flask, render_template, redirect, url_for, request, session

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import CFG, INVALID_FORM
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError
from dnx_configure.dnx_system_info import System

def load_page():
    whitelist = load_configuration('whitelist.json')['whitelist']

    exceptions = whitelist['exception']
    domain_whitelist = whitelist['domain']
    ip_whitelist = whitelist['ip_whitelist']

    for domain, info in domain_whitelist.items():
        st_offset = System.calculate_time_offset(info['time'])

        domain_whitelist[domain]['time'] = System.format_date_time(st_offset)

    whitelist_settings = {
        'domain_whitelist': domain_whitelist, 'exceptions': exceptions,
        'ip_whitelist': ip_whitelist
    }

    return whitelist_settings

def update_page(form):
    if ('wl_add' in form):
        domain = form.get('domain', None)
        timer = form.get('rule_length', None)
        if (not domain or not timer):
            return INVALID_FORM

        try:
            validate.domain(domain)
            validate.timer(timer)
        except ValidationError as ve:
            return ve
        else:
            configure.add_proxy_domain(domain, timer, ruleset='whitelist')

    elif ('wl_remove' in form):
        domain = form.get('wl_remove', None)
        if (not domain):
            return INVALID_FORM

        configure.del_proxy_domain(domain, ruleset='whitelist')

    elif ('exc_add' in form):
        domain = form.get('domain', None)
        reason = form.get('reason', None)
        if (not domain or not reason):
            return INVALID_FORM

        try:
            validate.domain(domain)
            validate.standard(reason)
        except ValidationError as ve:
            return ve
        else:
            configure.set_proxy_exception(domain, CFG.ADD, reason, ruleset='whitelist')

    elif ('exc_remove' in form):
        domain = form.get('exc_remove', None)
        if (not domain):
            return INVALID_FORM

        configure.set_proxy_exception(domain, CFG.DEL, ruleset='whitelist')

    elif ('ip_wl_add' in form):
        whitelist_ip = form.get('ip_wl_ip', None)
        whitelist_user = form.get('ip_wl_user', None)
        whitelist_type = form.get('ip_wl_type', None)

        whitelist_settings = {'user': whitelist_user, 'type': whitelist_type}
        if not all([whitelist_ip, whitelist_type, whitelist_user]):
            return INVALID_FORM

        try:
            validate.ip_address(whitelist_ip)
            validate.add_ip_whitelist(whitelist_ip, whitelist_settings)
        except ValidationError as ve:
            return ve
        else:
            configure.add_proxy_ip_whitelist(whitelist_ip, whitelist_settings)

    elif ('ip_wl_remove' in form):
        whitelist_ip = form.get('ip_wl_ip', None)
        whitelist_type = form.get('ip_wl_type', None)

        if (not whitelist_ip or not whitelist_type):
            return INVALID_FORM

        try:
            validate.ip_address(whitelist_ip)
            validate.del_ip_whitelist(whitelist_type)
        except ValidationError as ve:
            return ve
        else:
            configure.del_proxy_ip_whitelist(whitelist_ip, whitelist_type)

    else:
        return INVALID_FORM