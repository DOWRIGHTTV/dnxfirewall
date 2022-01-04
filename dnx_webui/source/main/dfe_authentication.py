#!/usr/bin/python3

import time
import csv
import hashlib
import threading

from functools import wraps
from flask import Flask, redirect, render_template, request, session, url_for

from dnx_gentools.def_constants import HOME_DIR
from dnx_gentools.file_operations import load_configuration
from dnx_routines.logging.log_main import direct_log
from dnx_routines.database.ddb_connector_sqlite import DBConnector


LOG_NAME = 'logins'


class Authentication:
    def __init__(self):
        self._time_expired = threading.Event()

    @classmethod
    def user_login(cls, form, login_ip):
        '''function to authenticate user to the dnx web frontend. pass in flask form and source ip. return will be a
        boolean representing whether user is authenticated/authorized or not.'''
        self = cls()

        threading.Thread(target=self._login_timer).start()

        authorized, username, user_role = self._user_login(form)
        if (authorized):
            direct_log(
                LOG_NAME, 'notice', f'User {username} successfully logged in from {login_ip}.'
            )

        else:
            direct_log(
                LOG_NAME, 'warning', f'Failed login attempt for user {username} from {login_ip}.'
            )

        while not self._time_expired:
            time.sleep(.202)

        return authorized, username, user_role

    @staticmethod
    # see if this is safe. if this returns something outside of dictionary, error will occur.
    def get_user_role(username):
        local_accounts = load_configuration('logins', filepath='dnx_webui/data')['users']
        try:
            return local_accounts[username]['role']
        except KeyError:
            return None

    @staticmethod
    def hash_password(username, password):
        salt_one = len(username)
        salt_two = len(password)

        # salt value will be placed at the calculated index in username
        if (salt_two > salt_one):
            salt = salt_two/salt_one
        else:
            salt = salt_one/salt_two

        # floor division to index ~midway point of username
        index = salt_one//2
        part_one = username[:index]
        part_two = username[index:]

        # salt is compounded from username and initial salt value then appended to password
        salt = f'{part_one}{salt}{part_two}'
        password = f'{password}{salt}'.encode('utf-8')

        # calculate the hash, then use a part of the hash as salt for the final hashed value
        hash_object = hashlib.sha256(password).hexdigest()
        hash_part = f'{hash_object}'[:salt_one*2]

        hash_total = f'{hash_part}{hash_object}'.encode('utf-8')
        hash_total = hashlib.sha256(hash_total)

        return hash_total.hexdigest()

    def _user_login(self, form):
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
    def _user_authorized(username, hexpass):
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

# web ui page authorization handler
def user_restrict(*authorized_roles):
    '''user authorization decorator to limit access according to account roles. apply this decorator
    to any flask function associated with page route with the user rules in decorator argument.'''

    def decorator(function_to_wrap):

        @wraps(function_to_wrap)
        def wrapper(*_):
            # will redirect to login page if user is not logged in
            user = session.get('user', None)
            if (not user):
                return redirect(url_for('dnx_login'))

            # NOTE: this is dnx local tracking of sessions. not to be confused with flask session tracking. they
            # are essentially copies of each other, but dnx is used to track all active sessions.
            # NOTE: currently, dnx session data limits connections to 1 per user. this may change in the future, but
            # some enterprise systems have similar restrictions or multiple tab restrictions.
            session_tracker = load_configuration('session_tracker', filepath='dnx_webui/data')['active_users']

            persistent_session_data = session_tracker.get(user, None)
            if (not persistent_session_data or persistent_session_data['remote_addr'] != request.remote_addr):
                return redirect(url_for('dnx_login'))

            # will redirect to not authorized page if the user role does not match
            # requirements for the page
            if (persistent_session_data['role'] not in authorized_roles):
                session.pop('user', None)

                return render_template(
                    f'{Flask.template_path}/main/not_authorized.html', navi=True, login_btn=True, idle_timeout=False)

            Flask.app.dnx_session_data[user] = user

            # ==================================
            # open db connection if not already
            # ==================================
            # TODO: make sure this is thread safe
            if (Flask.app.dnx_object_database is None):
                # Flask.app.dnx_object_database = DBConnector(table='notsureyet', readonly=True, connect=False)

                with open(f'{HOME_DIR}/dnx_webui/data/builtin_fw_objects.csv') as fw_objects:
                    Flask.app.dnx_object_database = [x for x in csv.reader(fw_objects) if x and '#' not in x[0]][1:]

            # flask page function
            page_action = function_to_wrap(persistent_session_data)

            return page_action

        return wrapper
    return decorator
