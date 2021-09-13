#!/usr/bin/python3

import os, sys
import time
import hashlib
import threading

from functools import wraps
from flask import request, redirect, url_for, render_template, session

from dnx_sysmods.configure.file_operations import load_configuration
from dnx_sysmods.logging.log_main import LogHandler as Log

LOG_NAME = 'logins'


class Authentication:
    def __init__(self):
        self._time_expired = threading.Event()

    @staticmethod
    ## see if this is safe. if use returns something outside of dictionary, error will occur.
    def get_user_role(username):
        local_accounts = load_configuration('logins', filepath='dnx_webui/data')['users']
        try:
            return local_accounts[username]['role']
        except KeyError:
            return None

    @classmethod
    def user_login(cls, form, login_ip):
        '''function to authenticate user to the dnx web frontend. pass in flask form and source ip. return
        will be a boolean representing whether user is authenticated/authorized or not.'''
        self = cls()

        threading.Thread(target=self._login_timer).start()

        authorized, username, user_role = self._user_login(form, login_ip)
        if (authorized):
            Log.simple_write(
                LOG_NAME, 'notice', f'User {username} successfully logged in from {login_ip}.'
            )

        else:
            Log.simple_write(
                LOG_NAME, 'warning', f'Failed login attempt for user {username} from {login_ip}.'
            )

        while not self._time_expired:
            time.sleep(.202)

        return authorized, username, user_role

    def _user_login(self, form, login_ip):
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

    def hash_password(self, username, password):
        salt_one = len(username)
        salt_two = len(password)

        if (salt_two > salt_one):
            salt = salt_two/salt_one
        else:
            salt = salt_one/salt_two

        index = int(float(salt_one/2))
        part_one = username[:index]
        part_two = username[index:]

        salt = f'{part_one}{salt}{part_two}'
        password = f'{password}{salt}'.encode('utf-8')

        hash_object = hashlib.sha256(password).hexdigest()
        hash_part = f'{hash_object}'[:salt_one*2]

        hash_total = f'{hash_part}{hash_object}'.encode('utf-8')
        hash_total = hashlib.sha256(hash_total)

        return hash_total.hexdigest()

    def _user_authorized(self, username, hexpass):
        local_accounts = load_configuration('logins', filepath='dnx_webui/data')['users']
        try:
            password = local_accounts[username]['password']
        except KeyError:
            return False
        else:
            # returning True on password match else False
            return password == hexpass

    def _login_timer(self):
        time.sleep(.6)
        self._time_expired.set()

# web ui page autorization handler
def user_restrict(*authorized_roles):
    '''user authorization decorator to limit access according to account roles. apply this decorator
    to any flask function associated with page route with the user rules in decorator argument.'''

    def decorator(function_to_wrap):

        @wraps(function_to_wrap)
        def wrapper(*args):
            # will redirect to login page if user is not logged in
            user = session.get('user', None)
            if not user:
                return redirect(url_for('dnx_login'))

            # NOTE: this is dnx local tracking of sessions. not to be confused with flask session tracking. they
            # are essentially copies of each other, but dnx is used to track all active sessions.
            # NOTE: currently, dnx session data limits connections to 1 per user. this may change in the future, but
            # some enterprise systems have similar restrictions or multiple tab restrictions.
            session_tracker = load_configuration('session_tracker', filepath='dnx_webui/data')['active_users']

            dnx_session_data = session_tracker.get(user['name'])
            if (not dnx_session_data or dnx_session_data['remote_addr'] != request.remote_addr):
                return redirect(url_for('dnx_login'))

            # will redirect to not authorized page if the user role does not match
            # requirements for the page
            # user_role = Authentication.get_user_role(username) # NOTE: should be deprecated by dnx session tracker
            if (dnx_session_data['role'] not in authorized_roles):
                session.pop('user', None)

                return render_template('dnx_not_authorized.html', navi=True, login_btn=True, idle_timeout=False)

            dnx_session_data[user['name']] = user

            # flask page function
            page_action = function_to_wrap(dnx_session_data)

            return page_action

        return wrapper
    return decorator
