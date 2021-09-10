#!/user/bin/env python3

import os, sys
import time
import json

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-2]))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import SHELL_SPACE
from dnx_shell.dnx_shell_standard import Standard
from subprocess import run, CalledProcessError, PIPE


class DNS:
    def __init__(self, Main):
        self.Main = Main
        self.conn = Main.conn

        with open(f'{HOME_DIR}/dnx_shell/commands.json', 'r') as commands:
            valid_commands = json.load(commands)

        with open(f'{HOME_DIR}/dnx_system/data/dns_server.json', 'r') as categories:
            category = json.load(categories)

        self.valid = valid_commands['main']['configuration']['dns']
        self.valid_dns = category['dns_server']

        self.mod = 'dns'

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
        comm, arg, option, option2 = self.Standard.HandleArguments(data)

        if (comm not in self.valid['commands']):
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

        elif (comm in {'show', 'set', 'clear', 'enable', 'disable'} and not arg and not option):
            valid_args = self.valid['commands'][comm]['args'].strip('!')
            for arg, value in self.valid[valid_args].items():
                # if (comm == 'show' and arg in {'category', 'tld'}):
                #     arg = value['syntax']
                info = value['info']
                arg = self.Standard.CalculateSpace(arg)
                self.conn.send(f'{arg} {info}\n'.encode('utf-8'))

            return

        # commands length 2
        if (arg_len < 2):
            return

        args = self.Standard.GrabArgs(comm)
        status = self.Standard.ValidateArgs(arg, args)
        if (not status):
            self.Standard.SendNotice(f'invalid argument. use "{comm}" command for all available arguments.')
            return

        elif (comm == 'show'):
            valid_args = self.valid['commands'][comm]['args'].strip('!')
            if (arg in self.valid[valid_args]):
                self.ShowStatus(arg)
            else:
                self.Standard.SendNotice(f'invalid argument. use "show" command for all available options.')

            return

        elif (comm in {'enable', 'disable'}):
            self.ChangeStatus(comm, arg, option)

            return

        # command length 3
        if (arg_len < 3):
            if (arg in {'server1', 'server2'} and not option):
                arg = 'servers'

            if (status and not option and arg in {'server1', 'server2'}):
                self.Standard.SendNotice(f'missing server ip address. use "show {arg}" command to view current servers.')

                return

         # command length 4
        if (comm in {'set'}):
            if (arg in {'tls-retry'}):
                if (option not in {'5', '10', '60'}):
                    self.Standard.SendNotice(f'invalid retry amount. use 5, 10, or 60.')
                else:
                    self.ChangeStatus(comm, arg, option)
            elif (arg in {'server1', 'server2'}):
                status = self.Standard.ValidateIP(option)
                if (status and not option2):
                    self.Standard.SendNotice(f'missing server name after ip address.')

                elif (status):
                    status = self.Standard.AlphaNum(option2)
                    if (status):
                        self.ConfigureServer(arg, option, option2)

    def ShowStatus(self, arg):
        with open(f'{HOME_DIR}/dnx_system/data/dns_server.json', 'r') as settings:
            setting = json.load(settings)

        with open(f'{HOME_DIR}/dnx_system/data/dns_cache.json', 'r') as dns_cache:
            cache = json.load(dns_cache)

        if (arg == 'servers'):
            dns_servers = setting['dns_server']['resolvers']

            for server_info in dns_servers.values():
                name = server_info['name']
                server = server_info['ip_address']

                self.Standard.ShowSend(name, server)

        elif (arg == 'top-domains'):
            top_domains = cache['top_domains']
            if (not top_domains):
                self.Standard.SendNotice(f'no top-domains currently cached')

                return

            for domain, pos in top_domains.items():

                self.Standard.ShowSend(pos, domain)

        elif (arg in {'tls', 'udp-fallback'}):
            status = setting['dns_server']['tls']['enabled']
            if (arg == 'udp-fallback'):
                status = setting['dns_server']['tls']['fallback']

            if (status):
                status = 'ENABLED'
            else:
                status = 'DISABLED'

            self.Standard.ShowSend(arg, status)

        elif (arg == 'tls-retry'):
            arg_strip = arg.strip('tls-')
            retry_time = setting['dns_server']['tls'][arg_strip]
            retry_time /= 60

            retry_time = f'{int(retry_time)} Minutes'
            self.Standard.ShowSend(arg, retry_time)

    def ChangeStatus(self, comm, arg, option):
        with open(f'{HOME_DIR}/dnx_system/data/dns_server.json', 'r') as settings:
            setting = json.load(settings)

        if (comm == 'set' and arg == 'tls-retry'):
            tls = setting['dns_server']['tls']

            retry_amount = int(option) * 60
            if (tls['retry'] == retry_amount):
                self.Standard.SendNotice(f'tls-retry is already set to {option} minutes.')
            else:
                tls.update({'retry': retry_amount})

                with open(f'{HOME_DIR}/dnx_system/data/dns_server.json', 'w') as settings:
                    json.dump(setting, settings, indent=4)

                self.Standard.SendNotice(f'set {arg} to {option} minutes. use "show tls-retry" command to check current status.')

            return

        tls_settings = setting['dns_server']['tls']
        if (arg == 'udp-fallback'):
            arg2 = 'fallback'
        else:
            arg2 = 'enabled'

        old_status = tls_settings[arg2]
        if (comm == 'enable'):
            tls_settings.update({arg2: True})
        elif (comm == 'disable'):
             tls_settings.update({arg2: False})
        new_status = tls_settings[arg2]

        if (old_status == new_status):
            self.Standard.SendNotice(f'{arg} already {comm}d.')
        else:
            with open(f'{HOME_DIR}/dnx_system/data/dns_server.json', 'w') as settings:
                json.dump(setting, settings, indent=4)

            self.Standard.SendNotice(f'{comm}d {arg}. use "show {arg2}" command to check current status.')

    def ConfigureServer(self, arg, option, option2):
        with open(f'{HOME_DIR}/dnx_system/data/dns_server.json', 'r') as settings:
            setting = json.load(settings)

        dns_server = setting['dns_server']['resolvers'][arg]
        if (dns_server['ip_address'] == option):
            self.Standard.SendNotice(f'{arg} already configured to {option}.')
        else:
            dns_server.update({'name': option2, 'ip_address': option})

            with open(f'{HOME_DIR}/dnx_system/data/dns_server.json', 'w') as settings:
                json.dump(setting, settings, indent=4)

            self.Standard.SendNotice(f'set {arg} to {option}. use "show servers" command to check current status.')
