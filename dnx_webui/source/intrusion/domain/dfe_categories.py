#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.def_enums import CFG
from dnx_gentools.file_operations import ConfigurationManager, load_configuration

from source.web_validate import ValidationError, standard, convert_int


DISABLED = True

def load_page(menu_option):
    dns_proxy = load_configuration('profiles/profile_1', cfg_type='security/dns')
    userdefined_category = dns_proxy.get_items('categories->user_defined')

    ud_cat_lists = {}
    loaded_ud_category = {}
    userdefined_categories = []

    # TODO: fix this shit. its annoyingly bad right now.
    if (userdefined_category and not DISABLED):
        index = 0
        for i, entry, info in enumerate(userdefined_category):
            if (i % 3 == 0):
                ud_cat_list = {}

            ud_cat_list[entry] = bool(info['enabled'])

            if (len(ud_cat_list) == 3):
                ud_cat_lists[index] = ud_cat_list
                index += 1
        else:
            if (len(ud_cat_list) < 3):
                ud_cat_lists[index] = ud_cat_list

        for category in userdefined_category:
            if (category != 'enabled'):
                userdefined_categories.append(category)

        for x, cat in enumerate(userdefined_category, 1):

            if (x == menu_option):
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

def update_page(form):

    if (DISABLED):
        return 'user categories disabled for rework', 1

    menu_option = form.get('menu', '1')

    if ('ud_cat_add' in form):
        category = form.get('ud_category', None)
        if (not category):
            return INVALID_FORM, 1 # NOTE: get correct value for menu option

        try:
            standard(category)
            # validation errors can be raised here so keeping within try block
            configure_category(category, action=CFG.ADD)
        except ValidationError as ve:
            return ve, 1  # NOTE: get correct value for menu option

    elif ('ud_cat_remove' in form):
        category = form.get('ud_cat_remove')
        if (not category):
            return INVALID_FORM, 1  # NOTE: get correct value for menu option

        configure_category(category, action=CFG.DEL)

    elif ('cat_add_domain' in form):
        category = get_ud_category(menu_option)
        domain = form.get('ud_domain_name', None)
        reason = form.get('ud_domain_reason', None)
        if (not category):
            return 'a custom category must be created before adding domain rules.', 1  # NOTE: get correct value for
            # menu option

        elif (not domain or not reason):
            return INVALID_FORM, 1  # NOTE: get correct value for menu option

        try:
            standard(category)
            domain(domain)
            standard(reason)

            # validation errors can be raised here so keeping within try block
            configure_category_domain(category, domain, reason, action=CFG.ADD)
        except ValidationError as ve:
            return ve, 1 # NOTE: get correct value for menu option
        else:
            return f'added {domain} to {category}.', menu_option

    elif ('cat_del_domain' in form):
        category = get_ud_category(menu_option)
        domain = form.get('cat_del_domain', None)
        if (not domain or not category):
            return INVALID_FORM, 1  # NOTE: get correct value for menu option

        try:
            configure_category_domain(category, domain, action=CFG.DEL)
        except ValidationError as ve:
            return ve, 1  # NOTE: get correct value for menu option

    # else:
    #     return INVALID_FORM, 1 # NOTE: get correct value for the menu option

    return None, menu_option

# returning the category name of the currently selected menu option which is displayed by category name
# if an exception is raised. will return none, which will tell caller to show invalid form data error.
def get_ud_category(menu_option):
    menu_option = convert_int(menu_option)
    if (not menu_option):
        return None

    dns_proxy = load_configuration('dns_proxy')

    ud_categories = dns_proxy['categories']['user_defined']
    try:
        # correcting index since html loop starts at 1.
        return list(ud_categories)[menu_option-1]
    except Exception:
        return None

# TODO: shit is fucked up
# ==============
# CONFIGURATION
# ==============
def configure_category(category, *, action):
    with ConfigurationManager('dns_proxy') as dnx:
        custom_category_lists = dnx.load_configuration()

        ud_cats = custom_category_lists.get_list('categories->user_defined')
        if (action is CFG.DEL and category != 'enabled'):
            ud_cats.pop(category, None)

        elif (action is CFG.ADD):
            if (len(ud_cats) >= 6):
                raise ValidationError('Only support for maximum of 6 custom categories.')

            elif (category in ud_cats):
                raise ValidationError('Custom category already exists.')

            ud_cats[category] = {'enabled': False}

        dnx.write_configuration(custom_category_lists)

def configure_category_domain(category, domain, reason=None, *, action):
    with ConfigurationManager('dns_proxy') as dnx:
        custom_category_domains = dnx.load_configuration()

        ud_cats = custom_category_domains['categories']['user_defined']
        if (action is CFG.DEL and category != 'enabled'):
            ud_cats[category].pop(domain, None)

        elif (action is CFG.ADD):
            if (domain in ud_cats[category]):
                raise ValidationError('Domain rule already exists for this category.')
            else:
                ud_cats[category][domain] = reason

        dnx.write_configuration(custom_category_domains)