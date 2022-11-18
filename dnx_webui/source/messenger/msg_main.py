#!/usr/bin/env python3

from __future__ import annotations

from time import time as _time  # temp

from source.web_typing import *

from dnx_gentools.file_operations import load_configuration

from dnx_routines.database.ddb_connector_sqlite import DBConnector

def get_user_list(current_user: str) -> dict[str, list[int]]:
    web_users: ConfigChain = load_configuration('logins', filepath='/dnx_webui/data')
    active_users: ConfigChain = load_configuration('session_tracker', filepath='/dnx_webui/data')

    # [online, last seen] -> if online, last seen will be 0
    msg_users = {
        usr: [0, 0] for usr, settings in web_users.get_dict('users').items() if settings['role'] in ['admin', 'messenger']

    }
    # removes self from the contact list
    msg_users.pop(current_user)

    for user in msg_users:

        if user in active_users.get_list('active_users'):
            msg_users[user][0] = 1

        else:
            msg_users[user][1] = int(_time())

    return msg_users

# from, to, group, sent, message, expire  -> group is for future. probably wont have group for a bit.
def get_messages(sender: str, recipient: str) -> list:
    with DBConnector() as firewall_db:
        messages = firewall_db.execute('get_message', sender=sender, recipient=recipient)

    # messages = [
    #     ['dow', 'broke', False, int(_time()) - 100, 'Ay, what are you doing?', -1],
    #     ['broke', 'dow', False, int(_time()) - 50, 'Racing. Also, my shit is broken. fix it.', -1],
    #     ['dow', 'broke', False, int(_time()) - 10, 'Ok, well give me some pcaps.', -1]
    # ]

    return messages

def send_message() -> bool:
    with DBConnector() as firewall_db:
        status = firewall_db.execute('get_message', sender=sender, recipient=recipient)

    return status

def clear_user_chats():
    pass