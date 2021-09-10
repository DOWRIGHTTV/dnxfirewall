#!/user/bin/env python3

import os, sys
import time
import json
import re

HOME_DIR = os.environ.get('HOME_DIR', os.path.realpath('..'))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import SHELL_SPACE
from dnx_shell.dnx_shell_standard import Standard
from subprocess import run, CalledProcessError, PIPE


class Whitelist:
    def __init__(self, Main):
        self.Main = Main
        self.conn = Main.conn

        with open(f'{HOME_DIR}/dnx_shell/commands.json', 'r') as commands:
            valid_commands = json.load(commands)

        with open(f'{HOME_DIR}/dnx_system/data/whitelist.json', 'r') as settings:
            setting = json.load(settings)

        self.valid = valid_commands['main']['configuration']['whitelist']
        self.valid_whitelist = setting['whitelists']

        self.mod = 'whitelist'

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
        arg_count = len(data)
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

        elif (comm in {'show', 'add', 'delete'} and not arg):
            valid_args = self.valid['commands'][comm]['args'].strip('!')
            for arg, value in self.valid[valid_args].items():
                if (comm == 'show' and arg in {'exception'}):
                    arg = value['syntax']
                info = value['info']
                arg = self.Standard.CalculateSpace(arg)
                self.conn.send(f'{arg} {info}\n'.encode('utf-8'))

            return

        args = self.Standard.GrabArgs(comm)
        status = self.Standard.ValidateArgs(arg, args)
        if (not status):
            self.Standard.SendNotice(f'invalid argument. use "{comm}" command for all available arguments.')
            return

        # commands length 2
        if (arg_count < 2):
            return

        elif (comm == 'show'):
            self.ShowStatus(arg)

            return

        # commands length 3
        if (arg_count < 3):
            if (status and not option):
                self.Standard.SendNotice(f'missing option after argument.')

                return

        # commands length 4
        if (comm in {'add', 'delete'}):
            status = self.Standard.ValidateDomain(option)
            if (status and not option2):
                self.Standard.SendNotice(f'missing direction after argument. use "inbound", "outbound", or "both".')

                return
            if (status):
                if (arg == 'timebased'):
                    status2 = self.Standard.ValidateListTimes(option2)
                elif (arg == 'exceptions'):
                    status2 = self.Standard.AlphaNum(option2)
                if (status2):
                    self.AddWhitelist(comm, arg, option, option2)

    def ShowStatus(self, arg):
        with open(f'{HOME_DIR}/dnx_system/data/whitelist.json', 'r') as settings:
            setting = json.load(settings)

        arg2 = arg
        if (arg == 'exceptions'):
            self.SendDescription('domain', 'reason')
        elif (arg == 'timebased'):
            arg = 'domains'
            self.SendDescription('domain', 'time entered', 'expire time')
        elif (arg == 'ip'):
            arg = 'ip_whitelist'
            self.SendDescription('ip address', 'type', 'user')

        whitelist = setting['whitelists'][arg]
        if (not whitelist):
            self.Standard.SendNotice(f'no {arg2} objects configured')

            return

        for whitelist, info in whitelist.items():
            lists = self.Standard.CalculateSpace(whitelist)
            if (arg == 'exceptions'):
                info = info['reason']

            elif (arg == 'domains'):
                time = info['time']
                expire = info['expire']
                info = self.Standard.FormatDateTime(time)
                info = self.Standard.CalculateSpace(info, space=12, symbol='| ', dashes=False)
                info += str(self.Standard.FormatDateTime(expire))
            elif (arg == 'ip_whitelist'):
                user = info['user']
                info = info['type']
                info = self.Standard.CalculateSpace(info, space=10, symbol='| ', dashes=False)
                info += user
            wl_status = f'{lists} {info}'
            self.conn.send(f'{wl_status}\n'.encode('utf-8'))

    def AddWhitelist(self, comm, arg, option, option2):
        with open(f'{HOME_DIR}/dnx_system/data/whitelist.json', 'r') as settings:
            setting = json.load(settings)

        whitelist = setting['whitelists']
        if (arg == 'exception'):
            if (option in whitelist['exceptions']):
                self.Standard.SendNotice(f'{option} is already whitelisted.')

                return
            else:
                whitelist['exceptions'].update({option: {'reason': option2}})

        elif (option == 'timebased'):
            if (option in whitelist['domains']):
                self.Standard.SendNotice(f'{option} is already whitelisted.')

                return
            else:
                now = time.time()
                expire = now + (option2*60)
                whitelist['domains'].update({option: {'time': now, 'rule_length': option2*60, 'expire': expire}})

        syntax = self.valid['settings'][arg]['syntax']
        with open(f'{HOME_DIR}/dnx_system/data/whitelist.json', 'w') as settings:
            json.dump(setting, settings, indent=4)

        self.Standard.SendNotice(f'added {option}. use "show {syntax}" command to check current status.')

    def SendDescription(self, one, two, three=''):
        top = self.Standard.CalculateSpace(one, symbol='  ', dashes=False)
        top = top + ' ' + self.Standard.CalculateSpace(two, space=10, symbol='  ', dashes=False) + three
        self.conn.send(f'{top}\n'.encode('utf-8'))

    def ValidateCategory(self, arg, option):
        syntax = self.valid['settings'][arg]['syntax']
        valid_whitelist = self.valid_whitelist[syntax]
        if (arg == 'category'):
            valid_whitelist = valid_whitelist['default']

        if (option not in valid_whitelist):
            self.Standard.SendNotice(f'invalid {arg}. use "show {syntax}" to view all available {syntax}.')
        else:
            return True
