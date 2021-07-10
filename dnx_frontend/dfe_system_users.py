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

def load_page():
    users = load_configuration('logins', filepath='/dnx_frontend/data')['users']

    userlist = {}
    for account, info in users.items():
        userlist[account] = ('*****', info['role'])

    return userlist

def update_page(form):
    if ('user_add' in form):
        username = form.get('user_acct', None)
        password = form.get('user_password', None)
        role = form.get('user_role', None)

        if not all([username, password, role]):
            return INVALID_FORM

        account_info = {'username': username.lower(), 'password': password, 'role': role}
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

        if (username == session['username']):
            return 'Cannot delete logged in user.'

        else:
            account_info = {'username': username}

            configure.configure_user_account(account_info, action=CFG.DEL)

    else:
        return INVALID_FORM
