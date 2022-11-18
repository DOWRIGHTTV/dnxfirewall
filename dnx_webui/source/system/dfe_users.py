#!/usr/bin/python3

from __future__ import annotations

import re

from flask import session

from source.web_typing import *
from source.web_validate import *

from dnx_gentools.def_enums import CFG, DATA
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config

from source.main.dfe_authentication import Authentication
from source.web_interfaces import StandardWebPage

__all__ = ('WebPage',)

_VALID_ACCT_ROLES = ['admin', 'user', 'messenger', 'cli']


class WebPage(StandardWebPage):
    '''
    available methods: load, handle_ajax
    '''
    @staticmethod
    def load(form: Form) -> dict[str, Any]:
        users: dict = load_configuration('logins', filepath='/dnx_webui/data').get_dict('users')

        user_list = {}
        for account, info in users.items():
            user_list[account] = ('*****', info['role'])

        return user_list

    @staticmethod
    def update(form: Form) -> Optional[str]:
        if ('user_add' in form):
            account_info = config(**{
                'username': form.get('user_acct', DATA.MISSING),
                'password': form.get('user_password', DATA.MISSING),
                'role': form.get('user_role', DATA.MISSING)
            })

            if (DATA.MISSING in account_info.values()):
                return INVALID_FORM

            if error := validate_account_creation(account_info):
                return error.message

            configure_user_account(account_info, action=CFG.ADD)

        # TODO: should make it so admins can remove active users which would remove from session tracker effectively
        #  killing their active session.
            # NOTE: maybe have a button to kill sessions of other users of lesser priv so they can delete. this would
            # be similar to above, but require an extra/explicit step to remove logged in users of lesser priv.

        elif ('user_remove' in form):
            account_info = config(**{
                'username': form.get('user_remove', DATA.MISSING)
            })

            if (DATA.MISSING in account_info.values()):
                return INVALID_FORM

            if (username == session['user']):
                return 'Cannot delete the account you are currently logged in with.'

            else:
                configure_user_account(account_info, action=CFG.DEL)

        else:
            return INVALID_FORM

# ==============
# VALIDATION
# ==============
def validate_account_creation(account: config) -> Optional[ValidationError]:
    '''Convenience function wrapping username, password, and user_role input validation functions.

    Username value will be updated to .lower() on successful validation.
       '''

    if error := username(account.username):
        return error

    if error := password(account.password):
        return error

    if error := user_role(account.role):
        return error

    # setting username to lowercase seems cleaner here
    account.username = account.username.lower()

def username(user: str, /) -> Optional[ValidationError]:
    if (not user.isalnum()):
        return ValidationError('Username can only be alpha numeric characters.')

def password(passwd: str, /) -> Optional[ValidationError]:
    if (len(passwd) < 8):
        return ValidationError('Password does not meet length requirement of 8 characters.')

    criteria = (
        re.search(r'\d', passwd), re.search(r'[A-Z]', passwd),  # searching for digits & uppercase
        re.search(r'[a-z]', passwd), re.search(r'\W', passwd)   # searching for lowercase & symbols
    )

    if not all(criteria):
        return ValidationError('Password does not meet complexity requirements.')

def user_role(role: str, /) -> Optional[ValidationError]:
    if (role not in _VALID_ACCT_ROLES):
        return ValidationError('Invalid user role.')

# ==============
# CONFIGURATION
# ==============
def configure_user_account(account: config, action: CFG) -> Optional[ValidationError]:

    with ConfigurationManager('logins', file_path='/dnx_webui/data') as dnx:
        accounts: ConfigChain = dnx.load_configuration()

        users = accounts.get_list('users')

        if (action is CFG.DEL):
            del accounts[f'users->{account.username}']

        elif (action is CFG.ADD and account.username not in users):
            hexpass = Authentication.hash_password(account.username, account.password)

            accounts[f'users->{account.username}->password'] = hexpass
            accounts[f'users->{account.username}->role'] = account.role
            accounts[f'users->{account.username}->settings->theme'] = 'light'

        else:
            return ValidationError('User account already exists.')

        dnx.write_configuration(accounts.expanded_user_data)
