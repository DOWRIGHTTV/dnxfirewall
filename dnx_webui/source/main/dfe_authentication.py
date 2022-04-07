#!/usr/bin/python3

from __future__ import annotations

import hashlib
import threading

from functools import wraps
from flask import redirect, render_template, request, session, url_for

from dnx_gentools.def_constants import fast_sleep
from dnx_gentools.file_operations import load_configuration

from dnx_routines.logging import direct_log

# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING, Optional

if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Event


LOG_NAME = 'logins'


class Authentication:
    def __init__(self):
        self._time_expired: Event = threading.Event()

    @classmethod
    def user_login(cls, form: dict, login_ip: str) -> tuple:
        '''authenticate a user to the dnx web frontend.

        pass in the flask form and source ip. return will be a boolean representing whether the user is authenticated
        and authorized.
        '''
        self = cls()

        threading.Timer(.6, self._time_expired.set).start()

        authorized, username, user_role = self._user_login(form)
        if (authorized):
            direct_log(LOG_NAME, 'notice', f'User {username} successfully logged in from {login_ip}.')

        else:
            direct_log(LOG_NAME, 'warning', f'Failed login attempt for user {username} from {login_ip}.')

        while not self._time_expired:
            fast_sleep(.202)

        return authorized, username, user_role

    @staticmethod
    # see if this is safe. if this returns something outside of dictionary, error will occur.
    def get_user_role(username: str) -> Optional[str]:
        local_accounts = load_configuration('logins', filepath='dnx_webui/data')
        try:
            return local_accounts[f'users->{username}->role']
        except KeyError:
            return None

    @staticmethod
    def hash_password(username: str, password: str) -> str:
        salt_one: int = len(username)
        salt_two: int = len(password)

        # the salt value will be placed at the calculated index in username
        fsalt: float
        if (salt_two > salt_one):
            fsalt = salt_two/salt_one
        else:
            fsalt = salt_one/salt_two

        # floor division to index ~midway point of username
        index: float = salt_one//2
        part_one: str = username[:index]
        part_two: str = username[index:]

        # salt is compounded from username and initial salt value then appended to password
        salt: str = f'{part_one}{fsalt}{part_two}'
        password: bytes = f'{password}{salt}'.encode('utf-8')

        # calculate the hash, then use a part of the hash as salt for the final hashed value
        hash_object: str = hashlib.sha256(password).hexdigest()
        hash_part: str = f'{hash_object}'[:salt_one*2]

        hash_bytes: bytes = f'{hash_part}{hash_object}'.encode('utf-8')
        hash_total = hashlib.sha256(hash_bytes)

        return hash_total.hexdigest()

    def _user_login(self, form: dict) -> tuple[bool, Optional[str], Optional[str]]:
        password = form.get('password', None)
        username = form.get('username', '').lower()
        if (not username or not password):
            return False, None, None

        hexpass = self.hash_password(username, password)

        if not self._user_authorized(username, hexpass):
            return False, username, None

        # checking for web ui authorization (admins/users only. cli accounts will fail.)
        user_role = self.get_user_role(username)
        if user_role not in ['admin', 'user']:
            return False, username, None

        return True, username, user_role

    @staticmethod
    def _user_authorized(username: str, hexpass: str) -> bool:
        local_accounts = load_configuration('logins', filepath='dnx_webui/data')
        try:
            password = local_accounts[f'users->{username}->password']
        except KeyError:
            return False
        else:
            # returning True on password match else False
            return password == hexpass

# web ui page authorization handler
def user_restrict(*authorized_roles):
    '''user authorization decorator to limit access according to account roles.

    apply this decorator to any flask function associated with page route with the user rules in decorator argument.'''

    def decorator(function_to_wrap):

        @wraps(function_to_wrap)
        def wrapper(*_):
            # will redirect to login page if user is not logged in
            user = session.get('user', None)
            if (not user):
                return redirect(url_for('dnx_login'))

            # NOTE: this is dnx local tracking of sessions, not to be confused with flask session tracking.
            # they are essentially copies of each other, but dnx is used to track all active sessions.
            # NOTE: dnx session data limits connections to 1 per user.
            # this may change in the future, but some enterprise systems have similar or multiple tab restrictions.
            session_tracker = load_configuration('session_tracker', filepath='dnx_webui/data')

            logged_remote_addr = session_tracker.get(f'active_users->{user}->remote_addr')
            if (logged_remote_addr != request.remote_addr):
                session.pop('user', None)

                return redirect(url_for('dnx_login'))

            # will redirect to not authorized page if the user role does not match
            # requirements for the page
            logged_user_role = session_tracker.get(f'active_users->{user}->role')
            if (logged_user_role not in authorized_roles):
                session.pop('user', None)

                return render_template(
                    'main/not_authorized.html', navi=True, login_btn=True, idle_timeout=False)

            # flask page function
            page_action = function_to_wrap(session_tracker.expanded_user_data['active_users'][user])

            return page_action

        return wrapper
    return decorator
