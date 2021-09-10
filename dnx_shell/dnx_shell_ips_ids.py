#!/user/bin/env python3

import os, sys
import time
import json

HOME_DIR = os.environ.get('HOME_DIR', os.path.realpath('..'))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import SHELL_SPACE
from dnx_shell.dnx_shell_standard import Standard
from subprocess import run, CalledProcessError, PIPE


class IPS:
    def __init__(self, Main):
        self.Main = Main
        self.conn = Main.conn

        with open(f'{HOME_DIR}/dnx_shell/commands.json', 'r') as commands:
            valid_commands = json.load(commands)

        self.valid = valid_commands['main']['configuration']['ips']

        self.mod = 'ips-ids'

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

        elif (comm in {'show', 'set', 'enable', 'disable'} and not arg and not option):
            arg_list = self.valid['commands'][comm]['args'].strip('!')
            for arg, value in self.valid[arg_list].items():
                if (comm == 'show' and arg in {'category', 'tld'}):
                    arg = value['syntax']
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
            self.Standard.SendNotice(f'invalid argument. use "{comm}" command for all available options.')
            return

        elif (comm == 'show'):
            self.ShowStatus(arg)

            return

        # all subsequent commands require length of 2
        if (arg_len < 3):
            if (status and not option):
                arg_list = self.valid['commands'][comm]['args'].strip('!')
                arg_options = self.valid[arg_list][arg]['options']
                for option in arg_options:
                    arg2 = self.Standard.CalculateSpace(arg)
                    self.conn.send(f'{arg2} {option}\n'.encode('utf-8'))

            return

        if (comm in {'enable', 'disable'} and arg_len == 3):
            status = self.ValidateEnDisSetting(arg, option)
            if (status):
                self.ChangeStatus(comm, arg, option)

        if (arg_len < 4):
            if (status and not option2):
                if (arg == 'ddos' and option in {'tcp', 'udp', 'icmp'}):
                    option = self.Standard.CalculateSpace(option)
                    ddos_option = f'{option} *10-99*'
                    self.conn.send(f'{ddos_option}\n'.encode('utf-8'))
                elif (arg == 'portscan' and option in {'block-length'}):
                    option = self.Standard.CalculateSpace(option)
                    for val in [0, 24, 48, 72]:
                        portscan_option = f'{option} {val}'
                        self.conn.send(f'{portscan_option}\n'.encode('utf-8'))
                elif (arg == 'whitelist'):
                    option = self.Standard.CalculateSpace(option)
                    whitelist_option = f'{option} *reason*'
                    self.conn.send(f'{whitelist_option}\n'.encode('utf-8'))

            return

        elif (comm == 'set'):
            status = self.ValidateOptions(arg, option, option2)
            if (status):
                self.ConfigureOption(arg, option, option2)

    def ShowStatus(self, arg):
        with open(f'{HOME_DIR}/dnx_system/data/ips.json', 'r') as settings:
            setting = json.load(settings)

        if (arg == 'whitelist'):
            dns_servers = setting['ips']['whitelist']['dns_servers']
            if (dns_servers):
                status = 'ENABLED'
            else:
                status = 'DISABLED'

            dns_servers = self.Standard.CalculateSpace(arg)
            dns_servers_status = f'{dns_servers} {status}'
            self.conn.send(f'{dns_servers_status}\n'.encode('utf-8'))

            user_whitelist = setting['ips']['whitelist']['ip_whitelist']
            for ip_address, reason in user_whitelist.items():
                ip_address = self.Standard.CalculateSpace(ip_address)
                ip_address_whitelist = f'{ip_address} {reason}'
                self.conn.send(f'{ip_address_whitelist}\n'.encode('utf-8'))

        elif (arg in 'portscan'):
            portscan_settings = setting['ips']['port_scan']
            for setting, status in portscan_settings.items():
                if (setting != 'length'):
                    if (status):
                        status = 'ENABLED'
                    else:
                        status = 'DISABLED'
                else:
                    status = f'{status} hours'

                setting = self.Standard.CalculateSpace(setting)
                setting_status = f'{setting} {status}'
                self.conn.send(f'{setting_status}\n'.encode('utf-8'))

        if (arg == 'ddos'):
            status = setting['ips']['ddos']['enabled']
            if (status):
                status = 'ENABLED'
            else:
                status = 'DISABLED'

            prevention = self.Standard.CalculateSpace('prevention')
            prevention_status = f'{prevention} {status}'
            self.conn.send(f'{prevention_status}\n'.encode('utf-8'))

            limits = setting['ips']['ddos']['limits']
            for direction, settings in limits.items():
                self.conn.send(f'   {direction}\n'.encode('utf-8'))
                for protocol, pps in settings.items():
                    protocol = self.Standard.CalculateSpace(protocol)
                    protocol_pps = f'{protocol} {pps} pps'
                    self.conn.send(f'{protocol_pps}\n'.encode('utf-8'))

    def ChangeStatus(self, comm, arg, option):
        with open(f'{HOME_DIR}/dnx_system/data/ips.json', 'r') as settings:
            setting = json.load(settings)

        if (arg == 'portscan'):
            category = setting['ips']['port_scan']

        elif (arg == 'ddos'):
            category = setting['ips']['ddos']
            option = 'enabled'

        elif (arg == 'whitelist'):
            category = setting['ips']['whitelist']
            option = 'dns_servers'

        old_status = category[option]
        if (comm == 'enable'):
            category.update({option: True})
        elif (comm == 'disable'):
            category.update({option: False})
        new_status = category[option]

        if (old_status == new_status):
            self.Standard.SendNotice(f'{arg} {option} already {comm}d.')
        else:
            with open(f'{HOME_DIR}/dnx_system/data/ips.json', 'w') as settings:
                json.dump(setting, settings, indent=4)

            self.Standard.SendNotice(f'{comm}d {arg} {option}. use "show {arg}" command to check current status.')

    def ConfigureOption(self, arg, option, option2):
        with open(f'{HOME_DIR}/dnx_system/data/ips.json', 'r') as settings:
            setting = json.load(settings)

        option_setting = setting[arg]

        if (arg in {'portscan', 'ddos'}):
            if (arg == 'portscan'):
                option2 = 'length'

            old_status = option_setting[option][option2]
            option_setting.update({option: option2})
            new_status = option_setting[option][option2]
            if (old_status == new_status):
                self.Standard.SendNotice(f'{arg} {option} already set to {option2}.')
            else:
                with open(f'{HOME_DIR}/dnx_system/data/ips.json', 'w') as settings:
                    json.dump(setting, settings, indent=4)

                self.Standard.SendNotice(f'{arg} {option} set to {option2}. use "show {arg}" command to check current status.')

    def ValidateEnDisSetting(self, arg, option):
        if (arg == 'portscan'):
            if (option in {'prevention', 'reject'}):
                return True

        elif (arg == 'ddos'):
            if (option in {'prevention'}):
                return True

        elif (arg == 'whitelist'):
            if (option in {'dns'}):
                return True

        self.Standard.SendNotice(f'invalid {arg} setting. use "show {arg}" to view all available settings.')

    def ValidateOptions(self, arg, option, option2):
        if (arg == 'ddos'):
            if (option in {'tcp', 'udp', 'icmp'}):
                if (option2.isdigit() and int(option2) in range(10,100)):
                    return True
                else:
                    message = f'invalid packet per second. use "set ddos {option}" command for available options.'

            else:
                 message = f'invalid protocol. use "set ddos" command for available options.'

        elif (arg == 'portscan'):
            if (option in {'block-length'}):
                if (option2.isdigit() and int(option2) in {0,24,48,72}):
                    return True
                else:
                    message = 'invalid block length. use "set portscan block-length" command for available options.'

            else:
                message = 'invalid option. use "set portscan" command for available options.'


    def ValidateADDorDelete(self):
        if (arg == 'whitelist'):
            valid_ip = self.Standard.ValidateIP(option)
            if (valid_ip):
                valid_string = self.Standard.AlphaNum(option2)
                if (valid_string):
                    return True
                else:
                    message = 'invalid reason. must be alpha numeric characters.'
            else:
                message = 'invalid ip address.'

        self.Standard.SendNotice(message)
