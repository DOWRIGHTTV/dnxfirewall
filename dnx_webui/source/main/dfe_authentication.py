#!/usr/bin/python3

from __future__ import annotations

import hashlib
import threading

from functools import wraps
from flask import redirect, render_template, request, session, url_for, g as context_global

from source.web_typing import *

from dnx_gentools.def_constants import fast_time, fast_sleep
from dnx_gentools.def_enums import LOG, CFG
from dnx_gentools.file_operations import load_configuration, ConfigurationManager

from dnx_routines.logging.log_client import direct_log


__all__ = (
    'Authentication', 'user_restrict',

    'update_session_tracker', 'authenticated_session',
    'send_to_login_page', 'end_session_send_to_login_page',
)

LOG_NAME = 'logins'

class Authentication:
    '''Auth extension for WebUI.

    this class will access the Flask "request" and "session" data structures directly.
    '''
    def __init__(self):
        self._time_expired: Event = threading.Event()

    @classmethod
    def user_login(cls, *, specify_role: Optional[str] = None) -> tuple:
        '''authenticate a user to the dnx web frontend.

        return will be a boolean representing whether the user is authenticated and authorized.

        login success/fail will take the same amount of time to return to reduce timing based attack vulnerabilities.
        '''
        self = cls()

        threading.Timer(.6, self._time_expired.set).start()

        authorized, username, user_role = self._user_login(specify_role)
        if (authorized):
            direct_log(LOG_NAME, LOG.NOTICE, f'User {username} successfully logged in from {request.remote_addr}.')

        else:
            direct_log(LOG_NAME, LOG.WARNING, f'Failed login attempt for user {username} from {request.remote_addr}.')

        # blocks until expiration flag is set
        while not self._time_expired:
            fast_sleep(.202)

        if (authorized):
            update_session_tracker(username, user_role, request.remote_addr)

        return authorized, username, user_role

    @staticmethod
    # see if this is safe. if this returns something outside of dictionary, error will occur.
    def get_user_role(username: str) -> Optional[str]:
        local_accounts: ConfigChain = load_configuration('logins', filepath='dnx_webui/data')
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

    def _user_login(self, specify_role: Optional[str]) -> tuple[bool, Optional[str], Optional[str]]:
        password: str = request.form.get('password', '')
        username: str = request.form.get('username', '').lower()
        if (not username or not password):
            return False, None, None

        hexpass = self.hash_password(username, password)

        if not self._user_authorized(username, hexpass):
            return False, username, None

        user_role = self.get_user_role(username)

        # checking for explicit role match if specified.
        if (specify_role is not None and user_role == specify_role):
            return True, username, user_role

        # default role matches
        if (user_role in ['admin', 'user']):
            return True, username, user_role

        # no role match, no authorization
        return False, username, None

    @staticmethod
    def _user_authorized(username: str, hexpass: str) -> bool:
        local_accounts: ConfigChain = load_configuration('logins', filepath='dnx_webui/data')
        try:
            password = local_accounts[f'users->{username}->password']
        except KeyError:
            return False
        else:
            # returning True on password match else False
            return password == hexpass

# web ui page authorization handler
def user_restrict(*authorized_roles: str) -> Callable:
    '''user authorization decorator to limit access according to account roles.

    apply this decorator to any flask function associated with page route with the user rules in decorator argument.
    '''
    def decorator(function_to_wrap: Callable[[dict], str]):

        @wraps(function_to_wrap)
        def wrapper(*_):
            # will redirect to login page if user is not logged in
            if not (user := authenticated_session()):
                return send_to_login_page()

            # NOTE: this is dnx local tracking of sessions, not to be confused with flask session tracking.
            # they are essentially copies of each other, but dnx is used to track all active sessions.
            # NOTE: dnx session data limits connections to 1 per user.
            # this may change in the future, but some enterprise systems have similar or multiple tab restrictions.
            session_tracker: ConfigChain = load_configuration('session_tracker', filepath='dnx_webui/data')

            logged_remote_addr = session_tracker.get(f'active_users->{user}->remote_addr')
            if (logged_remote_addr != request.remote_addr):
                return end_session_send_to_login_page()

            # will redirect to not authorized page if the user role does not match requirements for the page
            logged_user_role = session_tracker.get(f'active_users->{user}->role')
            if (logged_user_role not in authorized_roles):

                # this prevents issues when going from the messenger to the admin panel
                if (logged_user_role == 'messenger'):
                    return end_session_send_to_login_page()

                return render_template(
                    'main/not_authorized.html', theme=context_global.theme, navi=True, login_btn=True, idle_timeout=False
                )

            session_info = {'user': user, **session_tracker.expanded_user_data['active_users'][user]}

            # flask page function
            page_action = function_to_wrap(session_info)

            return page_action

        return wrapper
    return decorator

def update_session_tracker(name: str, role: Optional[str] = None, remote_addr: Optional[str] = None, *, action: CFG = CFG.ADD) -> None:

    if (action is CFG.ADD and not remote_addr):
        raise ValueError('remote_addr must be specified if action is set to add.')

    with ConfigurationManager('session_tracker', file_path='dnx_webui/data') as session_tracker:
        persistent_tracker: ConfigChain = session_tracker.load_configuration()

        user_path = f'active_users->{name}'
        if (action is CFG.ADD):

            persistent_tracker[f'{user_path}->role'] = role
            persistent_tracker[f'{user_path}->remote_addr'] = remote_addr
            persistent_tracker[f'{user_path}->logged_in'] = fast_time()
            persistent_tracker[f'{user_path}->last_seen'] = fast_time()

            # adding user to flask session data structure
            session['user'] = name

        # NOTE: user must be removed from Flask session separately
        elif (action is CFG.DEL):
            try:
                del persistent_tracker[f'active_users->{name}']
            except KeyError:
                pass

        session_tracker.write_configuration(persistent_tracker.expanded_user_data)


def authenticated_session() -> Optional[str]:
    return session.get('user', None)

def send_to_login_page():
    '''determines correct login page, then returns a Response object redirect accordingly.
    '''
    login_page = 'messenger' if request.path == '/messenger' else 'dnx_login'

    return redirect(url_for(login_page))

def end_session_send_to_login_page(login_page: str = 'dnx_login'):
    '''1. remove user from Flask session data structure.
    2. determines correct login page, then returns a Response object redirect accordingly.
    '''
    login_page = 'messenger' if request.path == '/messenger' else 'dnx_login'

    session.pop('user', None)

    return redirect(url_for(login_page))
