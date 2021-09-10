#!/usr/bin/python3

import json
import sys, os

from flask import Flask, render_template, redirect, url_for, request, session

HOME_DIR = os.environ.get('HOME_DIR', os.path.realpath('..'))
sys.path.insert(0, HOME_DIR)

import dnx_sysmods.configure.configure as configure
import dnx_sysmods.configure.web_validate as validate

from dnx_sysmods.configure.def_constants import CFG, INVALID_FORM, DATA
from dnx_sysmods.configure.file_operations import load_configuration
from dnx_sysmods.configure.exceptions import ValidationError

def load_page(form):
    users = load_configuration('logins', filepath='/dnx_webui/data')['users']

    userlist = {}
    for account, info in users.items():
        userlist[account] = ('*****', info['role'])

    return userlist

def update_page(form):
    if ('user_add' in form):
        account_info = {
            'username': form.get('user_acct', DATA.INVALID),
            'password': form.get('user_password', DATA.INVALID),
            'role': form.get('user_role', DATA.INVALID)
        }

        if (DATA.INVALID in account_info.values()):
            return INVALID_FORM

        try:
            validate.account_creation(account_info)
        except ValidationError as ve:
            return ve
        else:
            configure.configure_user_account(account_info, action=CFG.ADD)

    # TODO: add validation ensuring user being deleted is not actively logged in which is now being tracked
    # locally by the session tracker. this addition along with current logged in user check can probably
    # be moved to a validation module function as done in most other form submission handlers.
    # TODO: should make it so admins can remove active users which would remove from session tracker effectively
    # killing their active session.
        # NOTE: maybe have a button to kill sessions of other users of lesser priv, then they could delete. this would
        # be similar to above, but require an extra/explicit step to remove logged in users of lesser priv.

    elif ('user_remove' in form):
        username = form.get('user_remove', None)

        if (not username):
            return INVALID_FORM

        if (username != session['user']['name']):

            configure.configure_user_account({'username': username}, action=CFG.DEL)

        else:
            return 'Cannot delete the account you are currently logged in with.'

    else:
        return INVALID_FORM
