#!/usr/bin/python3

import re

from typing import Optional
from flask import session

from dnx_gentools.def_constants import INVALID_FORM
from dnx_gentools.def_enums import CFG, DATA
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, config

from dnx_routines.configure.exceptions import ValidationError

from source.main.dfe_authentication import Authentication

def load_page(form):
    logins = load_configuration('logins', filepath='/dnx_webui/data')

    users = logins.searchable_user_data['users']

    user_list = {}
    for account, info in users.items():
        user_list[account] = ('*****', info['role'])

    return user_list

def update_page(form) -> Optional[str]:
    if ('user_add' in form):
        account_info = config(**{
            'username': form.get('user_acct', DATA.MISSING),
            'password': form.get('user_password', DATA.MISSING),
            'role': form.get('user_role', DATA.MISSING)
        })

        if (DATA.MISSING in account_info.values()):
            return INVALID_FORM

        error = validate_account_creation(account_info)
        if (error):
            return error.message

        configure_user_account(account_info, action=CFG.ADD)

    # TODO: add validation ensuring user being deleted is not actively logged in which is now being tracked
    # locally by the session tracker. this addition along with current logged in user check can probably
    # be moved to a validation module function as done in most other form submission handlers.
    # TODO: should make it so admins can remove active users which would remove from session tracker effectively
    # killing their active session.
        # NOTE: maybe have a button to kill sessions of other users of lesser priv, then they could delete. this would
        # be similar to above, but require an extra/explicit step to remove logged in users of lesser priv.

    elif ('user_remove' in form):
        account_info = config(**{
            'username': form.get('user_remove', DATA.MISSING)
        })

        if (DATA.MISSING in account_info.values()):
            return INVALID_FORM

        if (username == session['user']['name']):
            return 'Cannot delete the account you are currently logged in with.'

        else:
            configure_user_account(account_info, action=CFG.DEL)

    else:
        return INVALID_FORM

# ==============
# VALIDATION
# ==============

def validate_account_creation(account: config) -> Optional[ValidationError]:
    '''Convenience function wrapping username, password, and user_role input validation functions. Username value
       will be updated to .lower() on successful validation.'''

    try:
        username(account.username)
        password(account.password)
        user_role(account.role)
    except ValidationError as ve:
        return ve

    # setting username to lowercase seems cleaner here
    account.username = account.username.lower()

def username(user: str, /) -> Optional[ValidationError]:
    if (not user.isalnum()):
        return ValidationError('Username can only be alpha numeric characters.')

def password(passwd: str, /) -> Optional[ValidationError]:
    if (len(passwd) < 8):
        raise ValidationError('Password does not meet length requirement of 8 characters.')

    criteria = (
        re.search(r'\d', passwd), re.search(r'[A-Z]', passwd),  # searching for digits & uppercase
        re.search(r'[a-z]', passwd), re.search(r'\W', passwd)   # searching for lowercase & symbols
    )

    if not all(criteria):
        return ValidationError('Password does not meet complexity requirements.')

def user_role(role: str, /) -> Optional[ValidationError]:
    if (role not in ['admin', 'user', 'cli']):
        return ValidationError('Invalid user role.')

# ==============
# CONFIGURATION
# ==============

def configure_user_account(account: config, action: CFG) -> Optional[ValidationError]:

    with ConfigurationManager('logins', file_path='/dnx_webui/data') as dnx:
        accounts = dnx.load_configuration()

        userlist = accounts.searchable_user_data['users']

        if (action is CFG.DEL):
            del accounts[f'users->{account.username}']

        elif (action is CFG.ADD and account.username not in userlist):
            hexpass = Authentication.hash_password(account.username, account.password)

            accounts[f'users->{account.username}->password'] = hexpass
            accounts[f'users->{account.username}->role'] = account.role
            accounts[f'users->{account.username}->dark_mode'] = 0

        else:
            return ValidationError('User account already exists.')

        dnx.write_configuration(accounts.expanded_user_data)
