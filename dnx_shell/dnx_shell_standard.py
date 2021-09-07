#!/usr/bin/env python3

import os, sys
import time
import re
import ipaddress

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import SHELL_SPACE


class Standard:
    def __init__(self, CLI):
        self.CLI = CLI

        self.valid_domain = re.compile('(?P<domain>\w+)*\.(\w+)(\/.*)?')
        self.valid_ip = re.compile('^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        self.valid_mac = re.compile('(?:[0-9a-fA-F]:?){12}')

    def HandleArguments(self, data, length=1):
        comm = None
        arg = None
        option = None
        option2 = None
        if (len(data) == 1):
            comm = data[0]
        elif (len(data) == 2):
            comm, arg = data
        elif (len(data) == 3):
            comm, arg, option = data
        elif (len(data) == 4):
            comm, arg, option, option2 = data
        elif len(data) > length:
            self.SendNotice(f'too many arguments.')

        return comm, arg, option, option2

    def GrabArgs(self, comm):
        try:
            valid_args = self.CLI.valid['commands'][comm]['args']
            if ('!' in valid_args):
                comm = valid_args.strip('!')
                valid_args = self.CLI.valid[comm]

    #        print(valid_args)
        except KeyError:
            valid_args = []
        return valid_args

    def ValidateArgs(self, arg, args):
        if (arg not in args):
            return False
        else:
            return True

    def ValidateListTimes(self, time):
        if (not time.isdigit() or int(time) >= 1440):
            self.SendNotice('second option must be an integer between 1 and 1440 (24 hours)')
        else:
            return True

    def AlphaNum(self, user_input):
        if not (user_input.isalnum()):
            self.SendNotice(f'strings can only contain alpha numeric characters.')
        else:
            return True

    def ValidateDomain(self, domain):
        if (not self.valid_domain.match(domain)):
            self.SendNotice(f'invalid domain.')
        else:
            return True

    #fix the damn validation shit when you get back from store you shithead.
    def ValidateIP(self, ip_address):
        if (self.valid_ip.match(ip_address) or ip_address == 'none'):
            return True
        else:
            self.SendNotice(f'invalid ip address.')

    def ValidateMac(self, mac_address):
        if (self.valid_mac.match(mac_address) or mac_address in {'default', 'none'}):
            return True
        else:
            self.SendNotice(f'invalid mac address.')

    def ValidateNetmask(self, option):
        if (option == 'none'):
            return True

        elif (not option.isdigit()):
            self.SendNotice(f'netmask must be an integer in cidr notation. ')
        elif (int(option) not in range(24,31)):
            self.SendNotice(f'invalid netmask. use cidr between 24 and 30.')
        else:
            return True

    def ValidateDefaultGateway(self, default_gateway, ip_address, netmask):
        configured_network = ipaddress.IPv4Network(f'{ip_address}/{netmask}', strict=False)
        if (default_gateway not in configured_network):
            self.SendNotice(f'default gateway is not is invalid. ensure it is within the configured subnet.')
        else:
            return True

    def ConvertNetmask(self, option):
        netmask_to_cidr = {24 :'255.255.255.0', 25: '255.255.255.128', 26: '255.255.255.192', 27:
                            '255.255.255.224', 28: '255.255.255.240', 29: '255.255.255.248', 30:
                            '255.255.255.252', 31: '255.255.255.254', 32: '255.255.255.255'}

        return netmask_to_cidr[int(option)]

    def CalculateSpace(self, string, space=SHELL_SPACE, symbol='>', dashes=True):
        if (not dashes):
            return f'   {string}' + ' ' * (space - len(string)) + f'{symbol}'

        return f'   {string} ' + '-' * (space - len(string)) +  f'{symbol}'

    def SendNotice(self, notice):
        # if not self.CLI.mod:
        #     print(self.CLI.help_messages)
        # else:
        #     print(self.CLI.Main.help_messages)

        if (not self.CLI.mod and self.CLI.help_messages):
            self.CLI.conn.send(f'dnx#! {notice}\n'.encode('utf-8'))
        elif (self.CLI.mod and self.CLI.Main.help_messages):
            self.CLI.conn.send(f'dnx|{self.CLI.mod}#! {notice}\n'.encode('utf-8'))

    ## takes argument to show and the current setting, then called another method to return formatted string
    ## then sends over the cli connected socket.
    def ShowSend(self, arg, setting):
        arg = self.CalculateSpace(str(arg))
        arg_status = f'{arg} {setting}'
        self.CLI.conn.send(f'{arg_status}\n'.encode('utf-8'))

    def ChangeHelpSetting(self):
        if (self.CLI.mod):
            if (self.CLI.Main.help_messages):
                self.SendNotice(f'help messages disabled. type "commands" to view all available commands.')
                self.CLI.Main.help_messages = False
            else:
                self.CLI.Main.help_messages = True
                self.SendNotice(f'help messages enabled. type "commands" to view all available commands.')

        elif (not self.CLI.mod):
            if (self.CLI.help_messages):
                self.SendNotice(f'help messages disabled. type "commands" to view all available commands.')
                self.CLI.help_messages = False
            else:
                self.CLI.help_messages = True
                self.SendNotice(f'help messages enabled. type "commands" to view all available commands.')

    def FormatDateTime(self, epoch):
        f_time = time.ctime(epoch)
        f_time = f_time.split()

        format_date_time = f'{f_time[3]} {f_time[1]} {f_time[2]} {f_time[4]}'

        return format_date_time
