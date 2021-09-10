#!/usr/bin/env python3

import json
import sys, os

from flask import Flask, render_template, redirect, url_for, request, session

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-2]))
sys.path.insert(0, HOME_DIR)

import dnx_sysmods.configure.configure as configure
import dnx_sysmods.configure.web_validate as validate
from dnx_sysmods.configure.file_operations import load_configuration
from dnx_sysmods.configure.exceptions import ValidationError
from dnx_sysmods.configure.system_info import Services
from dnx_sysmods.configure.def_constants import UD_DOMAIN_HEIGHT, INVALID_FORM


# TODO: if system category gets disabled that had keyword enabled. it does not disable the keyword search.
def load_page(form):
    dns_proxy = load_configuration('dns_proxy')

    list_settings = dns_proxy['categories']
    system_cats = list_settings['default']
    userdefined_cats = list_settings['user_defined']

    tld_cats = dns_proxy['tlds']

    domain_settings = {
        'default': system_cats, 'tlds': tld_cats, 'user_defined': userdefined_cats
    }

    return domain_settings

#---------------------------------------------------------------------#
## -- Category List Configure -- ##
def update_page(form):
    if ('df_cat_update' in form):
        categories = form.getlist('category', None)
        # hardcoding required cats into list since they dont show up due to being html disabled
        categories.extend(['malicious', 'cryptominer'])
        try:
            validate.domain_categories(categories, ruleset='default')
        except ValidationError as ve:
            return ve
        else:
            configure.set_domain_categories(categories, ruleset='default')

    elif ('ud_cat_update' in form):
        categories = form.getlist('ud_category', None)
        try:
            validate.domain_categories(categories, ruleset='user_defined')
        except ValidationError as ve:
            return ve
        else:
            configure.set_domain_categories(categories, ruleset='user_defined')

    elif ('df_tld_update' in form):
        tlds = form.getlist('tld', None)
        try:
            validate.domain_categories(tlds, ruleset='tlds')
        except ValidationError as ve:
            return ve
        else:
            configure.set_domain_tlds(tlds)

    elif ('keyword_update' in form):
        keywords = form.getlist('keyword', None)
        try:
            validate.domain_category_keywords(keywords)
        except ValidationError as ve:
            return ve
        else:
            configure.set_domain_category_keywords(keywords)

    else:
        return INVALID_FORM
