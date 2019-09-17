#!/user/bin/env python3

import os, sys
import time
import json

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import SHELL_SPACE
from dnx_shell.dnx_shell_standard import Standard
from subprocess import run, CalledProcessError, PIPE


class IP:
    def __init__(self, Main):
        self.Main = Main
        self.conn = Main.conn

        with open(f'{HOME_DIR}/dnx_shell/commands.json', 'r') as commands:
            valid_commands = json.load(commands)

        with open(f'{HOME_DIR}/data/ip_proxy.json', 'r') as settings:
            setting = json.load(settings)

        self.valid = valid_commands['main']['configuration']['ip']
        self.valid_ip = setting['ip_proxy']

        self.mod = 'ip'

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

    def Parse(self, data):
        comm, arg, option, option2 = self.Standard.HandleArguments(data)
        if (comm not in self.valid['commands']):
            self.Standard.SendNotice(f'invalid command. type "commands" to view all available commands.')

            return

        # single word commands
        if (comm == 'exit'):
            return 'EXIT'

        elif (comm == 'help'):
            self.Standard.ChangeHelpSetting()
            return

        elif (comm == 'commands'):
            for cm, values in self.valid[comm].items():
                info = values['info']
                cm = self.Standard.CalculateSpace(cm)
                self.conn.send(f'{cm} {info}\n'.encode('utf-8'))

            return

        elif (comm in {'show', 'set', 'enable'} and not arg):
            valid_args = self.valid['commands'][comm]['args'].strip('!')
            for arg, value in self.valid[valid_args].items():
                if (comm == 'show' and arg in {'list', 'direction'}):
                    arg = value['syntax']
                info = value['info']
                arg = self.Standard.CalculateSpace(arg)
                self.conn.send(f'{arg} {info}\n'.encode('utf-8'))

            return

        # all subsequent commands require length of 2 or 3
        if (len(data) < 2):
            self.Standard.SendNotice(f'missing argument after command.')

            return

        elif (comm == 'show'):
            if (arg in self.valid_ip):
                self.ShowStatus(arg)
            else:
                self.Standard.SendNotice(f'invalid argument. use "show" command for all available options.')

            return

        args = self.Standard.GrabArgs(comm)
        status = self.Standard.ValidateArgs(arg, args)
        if (not status):
            self.Standard.SendNotice(f'invalid argument. use "{comm}" command for all available options.')
            return

        # all subsequent commands require length of 2
        if (len(data) < 3):
            if (status and not option):
                self.Standard.SendNotice(f'missing option after argument. use "show {arg}s" command for all available options.')

                return

        elif (comm in {'enable', 'disable'}):
            status = self.ValidateCategory(arg, option)
            if (status):
                self.ChangeStatus(comm, arg, option)

        # all subsequent require length 3
        if (len(data) < 4):
            if (status and not option2):
                self.Standard.SendNotice(f'missing direction after argument. use "inbound", "outbound", or "both".')

                return

        elif (comm in {'set'}):
            status = self.ValidateDirection(option2)
            if (status):
                self.ChangeDirection(option, option2)

        return True

    def ShowStatus(self, arg):
        with open(f'{HOME_DIR}/data/ip_proxy.json', 'r') as settings:
            setting = json.load(settings)

        if (arg == 'lists'):
            category = setting['ip_proxy']['lists']
            for cat, status in category.items():
                if (cat == 'tor'):
                    for node, status in category[cat].items():
                        if (status['enabled']):
                            status = 'ENABLED'
                        else:
                            status = 'DISABLED'

                        lists = self.Standard.CalculateSpace(f'tor_{node}')
                        lists_status = f'{lists} {status}'
                        self.conn.send(f'{lists_status}\n'.encode('utf-8'))
                    continue

                elif (status['enabled']):
                    status = 'ENABLED'
                else:
                    status = 'DISABLED'

                lists = self.Standard.CalculateSpace(cat)
                lists_status = f'{lists} {status}'
                self.conn.send(f'{lists_status}\n'.encode('utf-8'))

        elif (arg == 'directions'):
            category = setting['ip_proxy']['directions']
            for cat, status in category.items():
                status = status.upper()

                cat = self.Standard.CalculateSpace(cat)
                cat_status = f'{cat} {status}'
                self.conn.send(f'{cat_status}\n'.encode('utf-8'))

    def ChangeStatus(self, comm, arg, option):
        with open(f'{HOME_DIR}/data/ip_proxy.json', 'r') as settings:
            setting = json.load(settings)

        if (option == {'tor_entry', 'tor_exit'}):
            category = setting['ip_proxy']['lists']['tor']
            option = option.strip('tor_')

        elif (option == 'malware', 'compromised'):
            category = setting['ip_proxy']['lists']

        old_status = category[option]['enabled']
        if (comm == 'enable'):
            category[option].update({'enabled': True})
        elif (comm == 'disable'):
            category[option].update({'enabled': False})
        new_status = category[option]['enabled']

        if (old_status == new_status):
            self.Standard.SendNotice(f'{arg} {option} already {comm}d.')
        else:
            syntax = self.valid['settings'][arg]['syntax']
            with open(f'{HOME_DIR}/data/ip_proxy.json', 'w') as settings:
                json.dump(setting, settings, indent=4)

            self.Standard.SendNotice(f'{comm}d {option}. use "show {syntax}" command to check current status.')

    def ChangeDirection(self, option, option2):
        with open(f'{HOME_DIR}/data/ip_proxy.json', 'r') as settings:
            setting = json.load(settings)
        directions = setting['ip_proxy']['directions']

        old_direction = directions[option]
        if (option2 == old_direction):
            self.Standard.SendNotice(f'{option} direction already set to {option2}.')
        else:
            directions.update({option: option2})

            with open(f'{HOME_DIR}/data/ip_proxy.json', 'w') as settings:
                json.dump(setting, settings, indent=4)

            self.Standard.SendNotice(f'{option} direction set to {option2}. use "show directions" command to check current status.')

    def ValidateCategory(self, arg, option):
        syntax = self.valid['settings'][arg]['syntax']
        valid_ip = self.valid_ip[syntax]
        if (arg == 'category'):
            valid_ip = valid_ip['default']

        if (option not in valid_ip):
            self.Standard.SendNotice(f'invalid {arg}. use "show {syntax}" to view all available {syntax}.')
        else:
            return True

    def ValidateDirection(self, option2):
        if (option2 not in {'inbound', 'outbound', 'both'}):
            self.Standard.SendNotice(f'invalid direction. use "inbound", "outbound", or "both".')
        else:
            return True
