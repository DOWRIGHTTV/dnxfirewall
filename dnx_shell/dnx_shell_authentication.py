#!/usr/bin/python3

import os, time
import json
import hashlib
import threading

HOME_DIR = os.environ.get('HOME_DIR', os.path.dirname(os.path.dirname((os.path.realpath('__file__')))))

class Authentication:
    def __init__(self):
        with open(f'{HOME_DIR}/dnx_system/data/logins.json', 'r') as logins:
            logins = json.load(logins)

        self.local_accounts = logins['users']

        self.time_expired = False

    def RoleCheck(self, username):
        account_info = self.local_accounts.get(username, None)
        if (not account_info):
            return False

        local_account_role = account_info['role']
        if (local_account_role == 'cli'):
            return True
        else:
            return False

    def Login(self, username, password):
        cli_authorized = False

        threading.Thread(target=self.Timer()).start()

        if (username and password):
            username = username.lower()
            hexpass = self.HashPass(username, password)

            authorized = self.AuthorizeUser(username, hexpass)
            if (authorized):
                cli_authorized = self.RoleCheck(username)

        while True:
            if (self.time_expired):
                return cli_authorized

    def AuthorizeUser(self, username, hexpass):
        account_info = self.local_accounts.get(username, None)
        if (not account_info):
            return False

        password = account_info['password']
        if (password == hexpass):
            return True
        else:
            return False

    def HashPass(self, username, password):
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
        password = f'{password}{salt}'
        password = password.encode('utf-8')

        hash_object = hashlib.sha256(password)
        hash_object = hash_object.hexdigest()

        hash_part = str(hash_object)[:salt_one*2]

        hash_total = f'{hash_part}{hash_object}'
        hash_total = hash_total.encode('utf-8')
        hash_total = hashlib.sha256(hash_total)

        hexpass = hash_total.hexdigest()

        return hexpass

    def Timer(self):
        time.sleep(.5)
        self.time_expired = True
