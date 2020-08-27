#!/usr/bin/env python3


import os, sys

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_configure as configure
import dnx_configure.dnx_validate as validate

from dnx_configure.dnx_constants import CFG, INVALID_FORM
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_exceptions import ValidationError

def load_page(menu_option):
    dns_proxy = load_configuration('dns_proxy')['dns_proxy']
    userdefined_category = dns_proxy['categories']['user_defined']

    ud_cat_lists = {}
    loaded_ud_category = {}
    userdefined_categories = []

    if (userdefined_category):
        index = 0
        for i, entry in enumerate(userdefined_category):
            cat_enabled = userdefined_category[entry]['enabled']
            if (i % 3 == 0):
                ud_cat_list = {}
            if (cat_enabled):
                ud_cat_list[entry] = True
            else:
                ud_cat_list[entry] = False
            if (len(ud_cat_list) == 3):
                ud_cat_lists[index] = ud_cat_list
                index += 1
        else:
            if (len(ud_cat_list) < 3):
                ud_cat_lists[index] = ud_cat_list

        for category in userdefined_category:
            if (category != 'enabled'):
                userdefined_categories.append(category)

        for i, cat in enumerate(userdefined_category, 1):
            if (i == menu_option):
                loaded_ud_category = {cat: {}}
                load_category_rules = userdefined_category[cat]
                for i, rule in enumerate(load_category_rules):
                    if (rule != 'enabled'):
                        reason = userdefined_category[cat][rule]
                        loaded_ud_category[cat].update({i: [rule, reason]})

    category_settings = {
        'user_defined': ud_cat_lists, 'user_defined_rules': loaded_ud_category,
        'ud_list': userdefined_categories
    }

    return category_settings

#---------------------------------------------------------------------#
## -- Category List Configure -- ##
def update_page(form):
    menu_option = form.get('menu', '1')
    print(form)
    if ('ud_cat_add' in form):
        category = form.get('ud_category', None)
        if (not category):
            return INVALID_FORM, 1 # NOTE: get correct value for menu option

        print(f'validating the shit {category}')
        try:
            validate.standard(category)
            # validation errors can be raised here so keeping within try block
            configure.update_custom_category(category, action=CFG.ADD)
        except ValidationError as ve:
            return ve, 1 # NOTE: get correct value for menu option

    elif ('ud_cat_remove' in form):
        category = form.get('ud_cat_remove')
        if (not category):
            return INVALID_FORM, 1 # NOTE: get correct value for menu option

        configure.update_custom_category(category, action=CFG.DEL)

    elif ('cat_add_domain' in form):
        category = get_ud_category(menu_option)
        domain = form.get('ud_domain_name', None)
        reason = form.get('ud_domain_reason', None)
        if (not category):
            return 'a custom category must be created before adding domain rules.', 1 # NOTE: get correct value for menu option

        elif (not domain or not reason):
            return INVALID_FORM, 1 # NOTE: get correct value for menu option

        try:
            validate.standard(category)
            validate.domain(domain)
            validate.standard(reason)

            # validation errors can be raised here so keeping within try block
            configure.update_custom_category_domain(category, domain, reason, action=CFG.ADD)
        except ValidationError as ve:
            return ve, 1 # NOTE: get correct value for menu option
        else:
            return f'added {domain} to {category}.', menu_option

    elif ('cat_del_domain' in form):
        category = get_ud_category(menu_option)
        domain = form.get('cat_del_domain', None)
        if (not domain or not category):
            return INVALID_FORM, 1 # NOTE: get correct value for menu option

        try:
            configure.update_custom_category_domain(category, domain, action=CFG.DEL)
        except ValidationError as ve:
            return ve, 1 # NOTE: get correct value for menu option

    # else:
    #     return INVALID_FORM, 1 # NOTE: get correct value for menu option

    return None, menu_option

# returning the category name of the currently selected menu option which is displayed by category name
# if an exception is raised. will return none, which will tell caller to show invalid form data error.
def get_ud_category(menu_option):
    menu_option = validate.convert_int(menu_option)
    if (not menu_option):
        return None

    dns_proxy = load_configuration('dns_proxy')['dns_proxy']

    ud_categories = dns_proxy['categories']['user_defined']
    try:
        # correcting index since html loop starts at 1.
        return list(ud_categories)[menu_option-1]
    except Exception:
        return None