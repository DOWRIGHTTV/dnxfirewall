#!/user/bin/env python3

import json

from dnx_shell.dnx_shell_standard import Standard
from dnx_routines.configure.system_info import Interface as Int


class Interface:
    def __init__(self, Main):
        self.Main = Main
        self.conn = Main.conn

        with open(f'{HOME_DIR}/dnx_shell/commands.json', 'r') as commands:
            valid_commands = json.load(commands)

        self.valid = valid_commands['main']['configuration']['interface']
#        self.valid_interface = category['dns_server']

        self.mod = 'interfaces'

        self.interface_settings_pending = {'ip_address': {'setting': None, 'syntax': 'ip-address'}, 'netmask': {'setting': None, 'syntax': 'netmask'},
                                            'default_gateway': {'setting': None, 'syntax': 'default-gateway'}, 'mac_address':{'setting': None, 'syntax': 'mac-address'},
                                            'mode': {'setting': None, 'syntax': 'mode'}}

        self.Standard = Standard(self)
        self.ShowIPAddress(initial_load=True)

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

#        print(f'MODULE: {self.Main.help_messages}')
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

        elif (comm == 'configure'):
            self.ApplyPending()

        elif (comm == 'commands'):
            for cm, values in self.valid[comm].items():
                info = values['info']
                cm = self.Standard.CalculateSpace(cm)
                self.conn.send(f'{cm} {info}\n'.encode('utf-8'))

            return

        elif (comm in {'show'} and not arg):
            valid_args = self.valid['commands'][comm]['args'].strip('!')
            for arg, value in self.valid['settings'].items():
                info = value['info']
                arg = self.Standard.CalculateSpace(arg)
                self.conn.send(f'{arg} {info}\n'.encode('utf-8'))

        elif (comm in {'set'} and not arg):
            valid_args = self.valid['commands'][comm]['args'].strip('!')
            for arg, value in self.valid[valid_args].items():
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
            if (arg in {'ip-address'}):
                self.ShowIPAddress()
            elif (arg in {'mac-address'}):
                self.ShowMACAddress()
            elif (arg in {'pending'}):
                self.ShowPending()

            return

        elif (comm in {'enable', 'disable'}):
            self.ChangeStatus(comm, arg, option)

            return

        # command length 3
        if (arg_len < 3):
            if (status and not option):
                arg_list = self.valid['commands'][comm]['args'].strip('!')
                arg_options = self.valid[arg_list][arg]['options']
                for option in arg_options:
                    arg2 = self.Standard.CalculateSpace(arg)
                    self.conn.send(f'{arg2} {option}\n'.encode('utf-8'))

                return

         # command length 4
        if (comm in {'set'}):
            if (arg in {'mode'}):
                if (option not in {'dhcp', 'static'}):
                    self.Standard.SendNotice(f'invalid interface mode. use static or dhcp.')
                else:
                    self.InputSettings(arg, option)

            elif (arg in {'mac-address'}):
                status = self.Standard.ValidateMac(option)
                if (status):
                    self.InputSettings(arg, option)

            elif (arg in {'netmask'}):
                status = self.Standard.ValidateNetmask(option)
                if(status):
                    netmask = self.Standard.ConvertNetmask(option)
                    self.InputSettings(arg, netmask)

            elif (arg in {'ip-address', 'default-gateway'}):
                status = self.Standard.ValidateIP(option)
                if (status and not option):
                    self.Standard.SendNotice(f'missing ip address.')

                elif (status and arg in {'ip-address'}):
                    self.InputSettings(arg, option)

                elif (status and arg in {'default-gateway'}):
                    ip_address, netmask = self.CheckLoadedSettings()
                    if (ip_address and netmask ):
                        status = self.Standard.ValidateDefaultGateway(option, ip_address, netmask)
                        if (status):
                            self.InputSettings(arg, option)

    def InputSettings(self, arg, option):
        arg = arg.replace('-', '_')
        if (option == 'none'):
            option = 'not set'
        self.interface_settings_pending[arg].update({'setting': option})

        syntax = self.interface_settings_pending[arg].get('syntax')
        self.Standard.SendNotice(f'interface {syntax} pending change to {option}.')
        self.Standard.SendNotice(f'use "show pending" command to view set changes. use "configure" command to push pending settings.')

    def CheckLoadedSettings(self):
        if (self.interface_settings_pending['ip_address'].get('setting') and
                self.interface_settings_pending['netmask'].get('setting')):
            return (self.interface_settings_pending['ip_address'].get('setting'), self.interface_settings_pending['netmask'].get('setting'))
        else:
            self.Standard.SendNotice(f'ip address and subnet mask must be configured before default gateway.')
            return (None, None)

    #checking all pending items to ensure the user is informed about how to properly apply the settings. will notify
    #the user if the current pending changes are not valid.
    def CheckInterfaceMode(self, notice=False):
        status = set()
        for setting, info in self.interface_settings_pending.items():
            if (setting in {'mac_address', 'mode'}):
                continue

            if (info['setting']):
                status.add(True)

        #will check mode when applying settings or when using show pending command. the notice flags will be set
        #if the method is called from the show pending method otherwise it will not be set.
        if (self.interface_settings_pending['mode'].get('setting') != 'static' and status):
            if (not notice):
                self.Standard.SendNotice(f'interface mode must be set to static before applying pending settings.')
            else:
                self.Standard.SendNotice(f'note: interface mode must be set to static prior to applying any ip related settings.')
        else:
            return True

    def ShowPending(self):
        for info in self.interface_settings_pending.values():
            pending_name = info['syntax']
            pending_setting = info['setting']
            if (not pending_setting):
                pending_setting = 'not set'

            self.Standard.ShowSend(pending_name, pending_setting)
        self.CheckInterfaceMode(notice=True)

    def ShowIPAddress(self, initial_load=False):
        Inter = Int()
        with open(f'{HOME_DIR}/dnx_system/data/config.json', 'r') as settings:
           setting = json.load(settings)
        interface_settings = setting['settings']['interface']
        default_wan_mac = interface_settings['wan']['default_mac']
        configured_wan_mac = interface_settings['wan']['configured_mac']
        dhcp = interface_settings['wan']['dhcp']
        wan_int = interface_settings['outside']
        if (not configured_wan_mac):
            configured_wan_mac = default_wan_mac
        if (dhcp):
            wan_mode = 'dhcp'
        else:
            wan_mode = 'static'

        wan_ip = Inter.IP(wan_int)
        wan_netmask = Inter.Netmask(wan_int)
        wan_dfg = Inter.DefaultGateway(wan_int)
        if (initial_load):
            self.interface_settings_pending['mode'].update({'setting': wan_mode})
        else:
            self.Standard.ShowSend('ip-address', wan_ip)
            self.Standard.ShowSend('netmask', wan_netmask)
            self.Standard.ShowSend('default-gateway', wan_dfg)
            self.Standard.ShowSend('mode', wan_mode)

    def ShowMACAddress(self):
        with open(f'{HOME_DIR}/dnx_system/data/config.json', 'r') as settings:
           setting = json.load(settings)

        interface_settings = setting['settings']['interface']
        default_wan_mac = interface_settings['wan']['default_mac']
        configured_wan_mac = interface_settings['wan']['configured_mac']
        if (not configured_wan_mac):
            configured_wan_mac = default_wan_mac

        self.Standard.ShowSend('mac-address', configured_wan_mac)

    def ChangeMode(self, comm, arg, option):
        self.interface_settings_pending['mode'].update({'setting': option})

        self.Standard.SendNotice(f'interface mode set to {option}. use "show pending" command to check loaded configuration.')

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

    def ConfigureNetmask(self, netmask):
        self.interface_settings_pending['netmask'].update({'setting': netmask})

        self.Standard.SendNotice(f'netmask set to {netmask}. use "show pending" command to check loaded configuration.')

    def ApplyPending(self):
        if (self.interface_settings_pending == 'dhcp'):
            for setting, info in self.interface_settings_pending.items():
                if (setting in {'mac_address', 'mode'}):
                    continue

                if (info['setting']):
                    pass
