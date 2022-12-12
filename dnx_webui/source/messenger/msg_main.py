#!/usr/bin/env python3

# LABEL: CODE_NOT_STABLE

from flask import Flask, render_template, request, g as context_global

from source.main.dfe_authentication import *

app = Flask.app

# =================================
# SECURE MESSENGER
# =================================
import source.messenger.msg_control as messenger

# messenger will act like a single page application in that the uri will always be /messenger and chat will show if the
# user has been authenticated, otherwise a login screen will be displayed.
@app.route('/messenger', methods=['GET', 'POST'])
def messenger_login():
    page_settings = {
        'navi': False, 'login_btn': False, 'idle_timeout': False, 'login_error': ''
    }

    if not (user := authenticated_session()):

        if (request.method == 'POST'):

            authenticated, username, user_role = Authentication.user_login(specify_role='messenger')
            if (authenticated):
                return send_to_login_page()

            page_settings['login_error'] = 'Invalid Credentials. Please try again.'

        return render_template('messenger/login.html', theme=context_global.theme, **page_settings)

    # AUTHENTICATED USERS
    return messenger_chat()

@user_restrict('messenger', 'admin')  # NOTE: admin is for testing purposes only
def messenger_chat(session_info: dict) -> str:

    active_user = session_info['user']

    if (request.method == 'POST'):

        if ('change_recipients' not in request.form):

            if not messenger.send_message(active_user, request.form):
                return 'fuck'

    recipient, messages = messenger.get_messages(active_user, request.form)

    # loading user chats, then rendering template.
    page_settings = {
        'session_info': session_info,
        'contacts': messenger.get_user_list(active_user),
        'to_user': recipient,
        'messages': messages
    }

    return render_template('messenger/chat.html', theme=context_global.theme, **page_settings)
