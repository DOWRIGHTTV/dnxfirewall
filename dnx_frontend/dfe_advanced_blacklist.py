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
    blacklist = load_configuration('blacklist')['blacklist']

    exceptions = blacklist['exception']
    domain_blacklist = blacklist['domain']

    for domain, info in domain_blacklist.items():
        st_offset = System.calculate_time_offset(info['time'])

        domain_blacklist[domain]['time'] = System.format_date_time(st_offset)

    blacklist_settings = {
        'domain_blacklist': domain_blacklist,
        'exceptions': exceptions
    }

    return blacklist_settings

def update_page(form):
    if ('bl_add' in form):
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
            configure.add_proxy_domain(domain, timer, ruleset='blacklist')

    elif ('bl_remove' in form):
        domain = form.get('bl_remove', None)
        if (not domain):
            return INVALID_FORM

        configure.del_proxy_domain(domain, ruleset='blacklist')

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
            configure.set_proxy_exception(domain, CFG.ADD, reason, ruleset='blacklist')

    elif ('exc_remove' in form):
        domain = form.get('exc_remove', None)
        if (not domain):
            return INVALID_FORM

        configure.set_proxy_exception(domain, CFG.DEL, ruleset='blacklist')

    else:
        return INVALID_FORM
