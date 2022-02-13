#!/usr/bin/env python3

import json

from dnx_shell.dnx_shell_standard import Standard
from dnx_shell.dnx_shell_services import Services
from dnx_shell.dnx_shell_dns import DNS
from dnx_shell.dnx_shell_whitelist import Whitelist
from dnx_shell.dnx_shell_blacklist import Blacklist
from dnx_shell.dnx_shell_domain import Domain
from dnx_shell.dnx_shell_ip import IP
from dnx_shell.dnx_shell_interface import Interface
from dnx_shell.dnx_shell_ips_ids import IPS


class TopLevel:
    def __init__(self, conn):
        self.conn = conn

        with open(f'{HOME_DIR}/dnx_shell/commands.cfg', 'r') as commands:
            valid_commands = json.load(commands)

        self.valid = valid_commands['main']

        self.mod = None
        self.help_messages = True

        self.Standard = Standard(self)

    def CallNextLevel(self, result):
        if (result == 'services'):
            Services(self).CommandLoop()
        elif (result == 'domain'):
            Domain(self).CommandLoop()
        elif (result == 'ip'):
            IP(self).CommandLoop()
        elif (result == 'whitelist'):
            Whitelist(self).CommandLoop()
        elif (result == 'blacklist'):
            Blacklist(self).CommandLoop()
        elif (result == 'dns'):
            DNS(self).CommandLoop()
        elif (result == 'interface'):
            Interface(self).CommandLoop()
        elif (result == 'ips'):
            IPS(self).CommandLoop()

    def CommandLoop(self):
        while True:
            self.conn.send(f'dnx$> '.encode('utf-8'))
            data = self.conn.recv(1024).decode().strip('\r\n')
            data = data.lower().split()
            if not data:
                continue

            result = self.Parse(data)
            if (result == 'QUIT'):
                return 'QUIT'

            elif (result):
                self.CallNextLevel(result)

    def Parse(self, data):
        all_valid = self.valid['commands'].copy()
        all_valid.update(self.valid['configuration'])
        if (len(data) != 1):
            self.Standard.SendNotice(f'too many arguments')

        elif (data[0] not in all_valid):
            self.Standard.SendNotice(f'invalid command. type "commands" to view all available commands.')

        comm = data[0]
        # single word commands
        if (comm == 'quit'):
            return 'QUIT'
        elif (comm == 'help'):
            self.Standard.ChangeHelpSetting()
            return

        elif (comm == 'version'):
            self.ShowVersion()
            return

        elif (comm in {'list', 'commands'}):
            comm_list = self.valid
            if (comm == 'list'):
                comm = 'configuration'
            comm_list = self.valid[comm]
            for cm, values in comm_list.items():
                info = values['info']
                cm = self.Standard.CalculateSpace(cm)
                self.conn.send(f'{cm} {info}\n'.encode('utf-8'))

            return

        elif (comm in self.valid['configuration']):
            return comm

    def ShowVersion(self):
        with open(f'{HOME_DIR}/dnx_system/data/license.cfg', 'r') as configs:
            system = json.load(configs)

        with open(f'{HOME_DIR}/dnx_system/data/updates.cfg', 'r') as updates:
            update = json.load(updates)

        activated = system['license']['activated']
        validated = system['license']['validated']

        system_version = update['updates']['system']['version']
        domain_version = update['updates']['signature']['domain']['version']
        ip_version = update['updates']['signature']['ip']['version']
        self.system_current = update['updates']['system']['current']
        self.domain_current = update['updates']['signature']['domain']['current']
        self.ip_current = update['updates']['signature']['ip']['current']
        self.system_restart = update['updates']['system']['restart']
        self.domain_restart = update['updates']['signature']['domain']['restart']
        self.ip_restart = update['updates']['signature']['ip']['restart']
        self.system_error = update['updates']['system']['error']
        self.signature_error = update['updates']['signature']
        self.domain_error = update['updates']['signature']['domain']['error']
        self.ip_error = update['updates']['signature']['ip']['error']

        software_versions = {'status': 0, 'system': {'v': system_version, 's': 0}, 'domain': {'v': domain_version, 's': 0}, 'ip': {'v': ip_version, 's': 0}}
        for mod in ['system', 'domain', 'ip']:
            restart = getattr(self, f'{mod}_restart')
            error = getattr(self, f'{mod}_error')
            current = getattr(self, f'{mod}_current')
            if (not activated or not validated):
                software_versions[mod].update({'s': 'Unknown'})
            elif (current):
                software_versions[mod].update({'s': 'Up to Date'})
            else:
                software_versions[mod].update({'s': 'Out of Date'})
            if (restart):
                software_versions[mod].update({'s': 'restart required'})
            if (error):
                software_versions[mod].update({'s': 'update error (see web ui)'})

        if (not activated):
            software_versions.update({'status': 'awaiting activation'})
        if (not validated):
            software_versions.update({'status': 'awaiting validation'})

        for mod, value in software_versions.items():
            module = self.Standard.CalculateSpace(mod)
            if (mod == 'status'):
                mod_status = f'{module} {value}'
            else:
                version = value['v']
                version = self.Standard.CalculateSpace(version, space=11, symbol='|', dashes=None)
                status = value['s']
                mod_status = f'{module} {version} {status}'

            self.conn.send(f'{mod_status}\n'.encode('utf-8'))
