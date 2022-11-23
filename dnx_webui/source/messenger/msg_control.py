#!/usr/bin/env python3

from __future__ import annotations

from functools import lru_cache
from typing import NamedTuple
from hashlib import sha256

from source.web_typing import *

from dnx_gentools.def_constants import fast_time
from dnx_gentools.file_operations import load_configuration
from dnx_gentools.system_info import System

from dnx_routines.database.ddb_connector_sqlite import DBConnector

_format_msg_time = System.format_msg_time
class SECURE_MESSAGE(NamedTuple):
    sender: str
    recipients: str
    multi: int  # 0/1
    sent_at: int
    message: str
    expiration: int

    @lru_cache
    def to_string(self) -> str:
        return f'({self.sender},{self.recipients},{self.multi},{self.sent_at},{self.message},{self.expiration})'

    @lru_cache
    def msg_id(self) -> str:
        return sha256(self.to_string()).hexdigest()

    def msg_time(self) -> str:
        return _format_msg_time(self.sent_at)

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
            msg_users[user][1] = System.format_msg_time(fast_time())

    return msg_users

# TODO: figure out how time will be formatted. namedtuple method?
# from, to, group, sent, message, expire  -> group is for future. probably wont have group for a bit.
def get_messages(sender: str, form: Form) -> tuple[str, list[SECURE_MESSAGE]]:
    recipients = form.get('recipients', None)
    # basic input validation for now
    if (not recipients):
        return '', []

    with DBConnector() as firewall_db:
        messages = firewall_db.execute('get_messages', sender=sender, recipients=recipients)

    messages = [SECURE_MESSAGE(*row[1:]) for row in messages]

    return recipients, messages

def send_message(sender: str, form: Form) -> bool:

    recipients = form.get('recipients', None)
    message = form.get('message', None)

    # basic input validation for now
    if (not recipients or not message):
        return False

    multi = 0
    sent_at = fast_time()
    expiration = -1

    secure_message = SECURE_MESSAGE(sender, recipients, multi, sent_at, message, expiration)

    with DBConnector() as firewall_db:
        firewall_db.execute('send_message', msg_id=secure_message.msg_id(), message=secure_message)

    return not firewall_db.failed

def delete_message():
    pass

def purge_messages():
    pass
