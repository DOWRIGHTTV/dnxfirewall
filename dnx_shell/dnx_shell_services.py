#!/user/bin/env python3

import os, sys
import time
import json

HOME_DIR = os.environ.get('HOME_DIR', os.path.realpath('..'))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import SHELL_SPACE
from dnx_shell.dnx_shell_standard import Standard
from subprocess import run, CalledProcessError, PIPE


class Services:
    def __init__(self, Main):
        self.Main = Main
        self.conn = Main.conn

        with open(f'{HOME_DIR}/dnx_shell/commands.json', 'r') as commands:
            valid_commands = json.load(commands)

        self.valid = valid_commands['main']['configuration']['services']

        self.mod = 'services'

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
        comm, arg, _, _ = self.Standard.HandleArguments(data)
        if (comm not in self.valid['commands']):
            self.Standard.SendNotice(f'invalid command. type "commands" to view all available commands.')

        # single word commands
        if (comm == 'exit'):
            return 'EXIT'

        elif (comm == 'help'):
            self.Standard.ChangeHelpSetting()
            return

        elif (comm == 'status'):
            self.ShowStatus()

        elif (comm in {'show', 'start', 'restart', 'stop'} and not arg):
            valid_args = self.valid['commands'][comm]['args'].strip('!')
            for arg, value in self.valid[valid_args].items():
                if (comm == 'show' and arg in {'exception'}):
                    arg = value['syntax']
                info = value['info']
                arg = self.Standard.CalculateSpace(arg)
                self.conn.send(f'{arg} {info}\n'.encode('utf-8'))

        elif (comm in {'list', 'commands'}):
            if (comm == 'list'):
                comm = 'services'
            for cm, values in self.valid[comm].items():
                info = values['info']
                cm = self.Standard.CalculateSpace(cm)
                self.conn.send(f'{cm} {info}\n'.encode('utf-8'))

        # all subsequent commands require length of 2
        if (len(data) < 2):
            return # put invalid syntax here?

        args = self.Standard.GrabArgs(comm)
        status = self.Standard.ValidateArgs(arg, args)
        if (not status):
            self.Standard.SendNotice(f'invalid service. ex. {comm} dns-proxy')
            return

        if (comm in self.valid['commands']):
            if (status):
                self.ChangeStatus(comm, arg)

    def ChangeStatus(self, comm, service):
        # run(f'sudo systemctl {comm} {service}', shell=True)
        time.sleep(.5)
        action = self.valid['commands'][comm]['syntax']
        self.Standard.SendNotice(f'{action} {service}. use "status" command to check current status')

    def ShowStatus(self):
        all_status = []
        for service in self.valid['services']:
            try:
                service_status = run(f'sudo systemctl status dnx-{service}', shell=True, stdout=PIPE)
                service_status.check_returncode()

                status = '[+] UP'
            except CalledProcessError:
                status = '[-] DOWN'

            service = self.Standard.CalculateSpace(service)
            all_status.append(f'{service} {status}')

        for service_status in all_status:
            self.conn.send(f'{service_status}\n'.encode('utf-8'))
