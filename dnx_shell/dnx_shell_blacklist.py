#!/user/bin/env python3

import os, sys
import time
import json

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-3]))
sys.path.insert(0, HOME_DIR)

from dnx_shell.dnx_shell_standard import Standard


class Blacklist:
    def __init__(self, Main):
        self.Main = Main
        self.conn = Main.conn

        with open(f'{HOME_DIR}/dnx_shell/commands.json', 'r') as commands:
            valid_commands = json.load(commands)

        with open(f'{HOME_DIR}/dnx_system/data/blacklist.json', 'r') as settings:
            setting = json.load(settings)

        self.valid = valid_commands['main']['configuration']['blacklist']
        self.valid_blacklist = setting['blacklists']

        self.mod = 'blacklist'

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
            self.Standard.SendNotice(f'type "commands" to view all available commands.')

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

            elif (status):
                if (arg == 'timebased'):
                    status2 = self.Standard.ValidateListTimes(option2)
                elif (arg == 'exceptions'):
                    status2 = self.Standard.AlphaNum(option2)
                if (status2):
                    self.AddBlacklist(comm, arg, option, option2)

    def ShowStatus(self, arg):
        with open(f'{HOME_DIR}/dnx_system/data/blacklist.json', 'r') as settings:
            setting = json.load(settings)

        arg2 = arg
        if (arg == 'exceptions'):
            self.SendDescription('domain', 'reason')
        elif (arg == 'timebased'):
            arg = 'domains'
            self.SendDescription('domain', 'time entered', 'expire time')

        blacklist = setting['blacklists'][arg]
        if (not blacklist):
            self.Standard.SendNotice(f'no {arg2} objects configured')

            return

        for blacklist, info in blacklist.items():
            lists = self.Standard.CalculateSpace(blacklist)
            if (arg == 'exceptions'):
                info = info['reason']

            elif (arg == 'domains'):
                time = info['time']
                expire = info['expire']
                info = self.Standard.FormatDateTime(time)
                info = self.Standard.CalculateSpace(info, space=12, symbol='| ', dashes=False)
                info += str(self.Standard.FormatDateTime(expire))

            bl_status = f'{lists} {info}'
            self.conn.send(f'{bl_status}\n'.encode('utf-8'))

    def AddBlacklist(self, comm, arg, option, option2):
        with open(f'{HOME_DIR}/dnx_system/data/blacklist.json', 'r') as settings:
            setting = json.load(settings)

        blacklist = setting['blacklists']
        if (arg == 'exception'):
            if (option in blacklist['exceptions']):
                self.Standard.SendNotice(f'{option} is already blacklisted.')

                return
            else:
                blacklist['exceptions'].update({option: {'reason': option2}})

        elif (option == 'timebased'):
            if (option in blacklist['domains']):
                self.Standard.SendNotice(f'{option} is already blacklisted.')

                return
            else:
                now = time.time()
                expire = now + (option2*60)
                blacklist['domains'].update({option: {'time': now, 'rule_length': option2*60, 'expire': expire}})

        syntax = self.valid['settings'][arg]['syntax']
        with open(f'{HOME_DIR}/dnx_system/data/blacklist.json', 'w') as settings:
            json.dump(setting, settings, indent=4)

        self.Standard.SendNotice(f'added {option}. use "show {syntax}" command to check current status.')

    def SendDescription(self, one, two, three=''):
        top = self.Standard.CalculateSpace(one, symbol='  ', dashes=False)
        top = top + ' ' + self.Standard.CalculateSpace(two, space=10, symbol='  ', dashes=False) + three
        self.conn.send(f'{top}\n'.encode('utf-8'))

    def ValidateCategory(self, arg, option):
        syntax = self.valid['settings'][arg]['syntax']
        valid_blacklist = self.valid_blacklist[syntax]
        if (arg == 'category'):
            valid_blacklist = valid_blacklist['default']

        if (option not in valid_blacklist):
            self.Standard.SendNotice(f'invalid {arg}. use "show {syntax}" to view all available {syntax}.')
        else:
            return True
