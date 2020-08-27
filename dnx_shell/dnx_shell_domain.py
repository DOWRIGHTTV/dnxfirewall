#!/user/bin/env python3

import os, sys
import time
import json

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import SHELL_SPACE
from dnx_shell.dnx_shell_standard import Standard
from subprocess import run, CalledProcessError, PIPE


class Domain:
    def __init__(self, Main):
        self.Main = Main
        self.conn = Main.conn

        with open(f'{HOME_DIR}/dnx_shell/commands.json', 'r') as commands:
            valid_commands = json.load(commands)

        with open(f'{HOME_DIR}/dnx_system/data/dns_proxy.json', 'r') as categories:
            category = json.load(categories)

        self.valid = valid_commands['main']['configuration']['domain']
        self.valid_domain = category['dns_proxy']

        self.mod = 'domain'

        self.Standard = Standard(self)

    def CommandLoop(self):
        while True:
            self.conn.send(f'dnx|{self.mod}$> '.encode('utf-8'))
            data = self.conn.recv(1024).decode().strip('\r\n')
            data = data.lower().split()
            if not data:
                continue

            status = self.Parse(data)
            if (status == 'EXIT'):
                break
            elif (status == 'end'):
                return 'exit'

    def Parse(self, data):
        arg_len = len(data)
        comm, arg, option, _ = self.Standard.HandleArguments(data)

        if (comm is None):
            return
        elif (comm not in self.valid['commands']):
            self.Standard.SendNotice(f'invalid command. type "commands" to view all available commands.')

            return

        # single word commands
        if (comm == 'exit'):
            return 'EXIT'

        elif (comm == 'end'):
            return 'END'

        elif (comm == 'help'):
            self.Standard.ChangeHelpSetting()
            return

        elif (comm == 'commands'):
            for cm, values in self.valid[comm].items():
                info = values['info']
                cm = self.Standard.CalculateSpace(cm)
                self.conn.send(f'{cm} {info}\n'.encode('utf-8'))

            return

        elif (comm in {'show', 'enable', 'disable'} and not arg and not option):
            for arg, value in self.valid['settings'].items():
                if (comm == 'show' and arg in {'category', 'tld'}):
                    arg = value['syntax']
                info = value['info']
                arg = self.Standard.CalculateSpace(arg)
                self.conn.send(f'{arg} {info}\n'.encode('utf-8'))

            return

        # commands length 2
        if (arg_len < 2):
            return

        elif (comm == 'show'):
            if (arg in self.valid_domain):
                self.ShowStatus(arg)
            else:
                self.Standard.SendNotice(f'invalid argument. use "show" command for all available options.')

            return

        elif (comm in {'enable', 'disable'} and arg_len == 2):
            self.ChangeStatus(comm, arg, option)

            return

        args = self.Standard.GrabArgs(comm)
        status = self.Standard.ValidateArgs(arg, args)
        if (not status):
            self.Standard.SendNotice(f'invalid argument. use "{comm}" command for all available options.')
            return

        # all subsequent commands require length of 2
        if (arg_len < 3):
            if (status and not option and comm in {'enable', 'disable'}):
                self.Standard.SendNotice(f'missing category. use "show categories" command for all available categories.')

                return

        if (comm in {'enable', 'disable'} and arg_len == 3):
            status = self.ValidateCategory(arg, option)
            if (status):
                self.ChangeStatus(comm, arg, option)

    def ShowStatus(self, arg):
        with open(f'{HOME_DIR}/dnx_system/data/dns_proxy.json', 'r') as settings:
            setting = json.load(settings)

        if (arg == 'keyword'):
            status = setting['dns_proxy']['keyword']['enabled']
            if (status):
                status = 'ENABLED'
            else:
                status = 'DISABLED'

            keyword = self.Standard.CalculateSpace(arg)
            keyword_status = f'{keyword} {status}'
            self.conn.send(f'{keyword_status}\n'.encode('utf-8'))

        elif (arg in 'categories', 'tlds'):
            category = setting['dns_proxy'][arg]
            if (arg == 'categories'):
                category = category['default']

            for cat, status in category.items():
                if (status['enabled']):
                    status = 'ENABLED'
                else:
                    status = 'DISABLED'

                cat = self.Standard.CalculateSpace(cat)
                cat_status = f'{cat} {status}'
                self.conn.send(f'{cat_status}\n'.encode('utf-8'))

    def ChangeStatus(self, comm, arg, option):
        with open(f'{HOME_DIR}/dnx_system/data/dns_proxy.json', 'r') as settings:
            setting = json.load(settings)

        if (arg == 'keyword'):
            category = setting['dns_proxy']['keyword']
            option = 'keyword'
            syntax = 'keyword'

        elif (arg == 'category'):
            category = setting['dns_proxy']['categories']['default']
            if (option in {'malicious', 'cryptominer'} and comm == 'disable'):
                self.Standard.SendNotice('critical categories cannot be disabled.')

                return

        elif (arg == 'tld'):
            category = setting['dns_proxy']['tlds']

        old_status = category[option]['enabled']
        if (comm == 'enable'):
            category[option].update({'enabled': True})
        elif (comm == 'disable'):
            category[option].update({'enabled': False})
        new_status = category[option]['enabled']

        if (old_status == new_status):
            if (arg == 'keyword'):
                self.Standard.SendNotice(f'{option} already {comm}d.')
            else:
                self.Standard.SendNotice(f'{arg} {option} already {comm}d.')
        else:
            syntax = self.valid['settings'][arg]['syntax']
            with open(f'{HOME_DIR}/dnx_system/data/dns_proxy.json', 'w') as settings:
                json.dump(setting, settings, indent=4)

            self.Standard.SendNotice(f'{comm}d {option}. use "show {syntax}" command to check current status.')

    def ValidateCategory(self, arg, option):
        syntax = self.valid['settings'][arg]['syntax']
        valid_domain = self.valid_domain[syntax]
        if (arg == 'category'):
            valid_domain = valid_domain['default']

        if (option not in valid_domain):
            self.Standard.SendNotice(f'invalid {arg}. use "show {syntax}" to view all available {syntax}.')
        else:
            return True
