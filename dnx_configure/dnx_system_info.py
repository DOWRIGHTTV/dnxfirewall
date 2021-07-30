#!/usr/bin/env python3

import os, sys
import json
import datetime
import socket
import fcntl

from copy import deepcopy
from time import time, ctime, sleep
from ipaddress import IPv4Address
from datetime import datetime, timedelta
from subprocess import run, CalledProcessError, DEVNULL

_HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, _HOME_DIR)

from dnx_configure.dnx_constants import str_join, FIVE_SEC
from dnx_configure.dnx_file_operations import load_configuration
from dnx_iptools.dnx_protocol_tools import convert_mac_to_bytes

__all__ = (
    'Interface', 'System', 'Services'
)


class Interface:
    '''This class is being depricated and being replaced by dnx_interface module in iptools dir.'''

    @staticmethod
    def ip_address(interface):
        output = run(f'ifconfig {interface}', shell=True, capture_output=True, text=True).stdout.splitlines(8)
        for line in output:
            if('inet' in line):
                line = line.strip().split()
                ip = line[1]
#                print(ip)
                return ip

    @staticmethod
    def mtu(interface):
        output = run(f'ifconfig {interface}', shell=True, capture_output=True, text=True).stdout.splitlines(8)
        for line in output:
            line = line.strip().split()
            if (line[3].isdigit()):
                mtu = int(line[3])
            else:
                mtu = 1500
#                print(mtu)
            return mtu

    @staticmethod
    def netmask(interface):
        output = run(f'ifconfig {interface}', shell=True, capture_output=True, text=True).stdout.splitlines(8)
        for line in output:
            if ('netmask' in line):
                line = line.strip().split()
                netmask = line[3]
#                print(netmask)
                return netmask

    @staticmethod
    def broadcast_address(interface):
        '''returns ip address object for the sent in interface networks broadcast address.'''
        output = run(f'ifconfig {interface}', shell=True, capture_output=True, text=True).stdout.splitlines(8)
        for line in output:
            if ('broadcast' in line):
                line = line.strip().split()
                broadcast = line[5]
#                print(broadcast)
                return IPv4Address(broadcast)

    @staticmethod
    def bandwidth():
        intstat = {}
        interface_bandwidth = load_configuration('interface_speed.json')
        for interface, value in interface_bandwidth.items():
            rx = str(round(int(value[0])/1024, 2)) + ' MB/s'
            tx = str(round(int(value[1])/1024, 2)) + ' MB/s'
            intstat[interface] = [rx, tx]
#        print(intstat)
        return intstat

    @staticmethod
    def mac_address(interface):
        '''returns string form mac address for sent in interface.'''
        output = run(f'ifconfig {interface}', shell=True, capture_output=True, text=True).stdout.splitlines(8)
        for line in output:
            if('ether' in line):
                line = line.strip().split()
                mac = line[1]
#                print(mac)
                return mac

    @staticmethod
    def default_gateway(interface):
        output = run('ip route', shell=True, capture_output=True, text=True).stdout.splitlines(8)
        for line in output:
            if('default' in line):
                dfg = line.split()[2]

                return dfg

    @staticmethod
    def default_gateways_mac_address(default_gateway):
        output = run('arp -n -e', shell=True, capture_output=True, text=True).stdout.splitlines(8)
        for line in output:
            line = line.split()
            if(line[0] == default_gateway):
                dfg_mac = line[2]

                return dfg_mac


class System:

    @staticmethod
    def restart():
        sleep(FIVE_SEC)
        run('sudo reboot', shell=True)

    @staticmethod
    def shutdown():
        sleep(FIVE_SEC)
        run('sudo shutdown', shell=True)

    @staticmethod
    # TODO: this seems completely fucked. ?????? are you high and drunk?
    def cpu_usage():
        with open('/proc/stat', 'r') as cpu:
            line = cpu.readline().split()

        idle = int(line[4])

        idle *= 100/sum([int(x) for x in line[1:]])

        percent = round(100 - idle, 2)
#        print(utilization)
        return f'{percent}%'

    @staticmethod
    def uptime():
        with open('/proc/uptime', 'r') as uptime:
            uptime = int(float(uptime.readline().split()[0]))

            uptime = str(timedelta(0, uptime))
            utime = uptime.split()

            if ('day' in uptime or 'days' in uptime):
                utime2 = utime[2].split(':')
                uptime = f'{utime[0]} day/s {utime2[0]} hour/s {utime2[1]} minute/s'

            else:
                utime0 = utime[0].split(':')
                uptime = f'0 day/s {utime0[0]} hour/s {utime0[1]} minute/s'
#        print(uptime)
        return uptime

    @staticmethod
    def ram_usage():
        '''returns available ram %. 69.82%'''
        total, available = None, None
        with open('/proc/meminfo', 'r') as memory:
            for line in memory:
                if ('MemTotal' in line):
                    total = int(line.split()[1])

                elif ('MemAvailable' in line):
                    available = int(line.split()[1])

                if (total and available): break

        ram = f'{round((total / available) * 10, 1)}%'
#        print(ram)
        return ram

    @staticmethod
    def calculate_time_offset(logged_time):
        '''returns modified time based on current time offset settings.'''
        logging = load_configuration('logging_client')['logging']

        offset = logging['time_offset']
        os_direction = offset['direction']
        os_amount    = offset['amount']
        offset       = int(f'{os_direction}{os_amount}') * 3600

        return logged_time + offset

    @staticmethod
    def format_log_time(epoch):
        '''return date and time in front end log format. 2019 Jun 24 19:08:15'''
        f_time = ctime(epoch).split()

        return f'{f_time[4]} {f_time[1]} {f_time[2]} {f_time[3]}'

    @staticmethod
    def format_date_time(epoch):
        '''return date and time in general format. 19:08:15 Jun 24 2019'''
        f_time = ctime(epoch).split()

        return f'{f_time[3]} {f_time[1]} {f_time[2]} {f_time[4]}'

    @staticmethod
    def format_time(epoch):
        '''return time in general 24h format. 19:08:15'''

        return f'{ctime(epoch).split()[3]}'

    @staticmethod
    def date(timestamp=None, string=False):
        '''return list of year, month, day of current system time. use timestamp
        argument to override. [2019, 06, 24]'''
        dt = datetime.now()
        if (timestamp):
            dt = datetime.fromtimestamp(timestamp)

        yr = f'{dt.year}'
        mo = f'{dt.month:02}'
        dy = f'{dt.day:02}'
        if (string):
            return str_join([yr, mo, dy])

        return [yr, mo, dy]

    @staticmethod
    def time():
        time = datetime.now()

        return [time.hour, time.minute]

    @staticmethod
    def dns_status():
        dns_servers_status = load_configuration('dns_server_status')
        dns_server = load_configuration('dns_server')['dns_server']

        tls_enabled = dns_server['tls']['enabled']
        dns_servers = dns_server['resolvers']
        dns_servers_copy = deepcopy(dns_servers)

        for server, server_info in dns_servers_copy.items():
            status = dns_servers_status.get(server_info['ip_address'], None)
            if (not status):
                tls = 'Waiting'
                dns = 'Waiting'
            else:
                dns = 'UP' if status['dns_up'] else 'Down'
                tls = 'UP' if status['tls_up'] else 'Down'

            if (not tls_enabled):
                tls = 'Disabled'

            dns_servers[server]['dns_up'] = dns
            dns_servers[server]['tls_up'] = tls

#        print(dnsstatus)
        return dns_servers

    @staticmethod
    def backups():
        backups = {}
        backup_dir = f'{_HOME_DIR}/dnx_system/config_backups'
        files = os.listdir(backup_dir)
        for file in files:
            name = file.replace('.tar', '')
            creation_time = os.stat(f'{backup_dir}/{file}').st_ctime # this is not accurate

            backups[name] = creation_time

#        print(backups)
        return backups

    @staticmethod
    # TODO: this can be refactored to follow dnat/snat format for parsing
    def firewall_rules(*, chain='GLOBAL_INTERFACE'):
        # getting list of all rules in specified chain
        output = run(
            f'sudo iptables -nL {chain} --line-number', shell=True, capture_output=True, text=True
        ).stdout.splitlines()

        # parsing output and formatting for use by front end
        firewallrules = []
        for rule in output[2:]:

            modified_rule = [x for i, x in enumerate(rule.split()) if i not in [3, 6]]
            # if ports are specified, it will be parsed then replaced with new value
            if (len(modified_rule) == 6):
                modified_rule[-1] = modified_rule[-1].lstrip('dpt:')

            elif (modified_rule[2] in ['icmp', 'all']):
                modified_rule.append('N/A')

            else:
                modified_rule.append('ANY')

            pos, action, proto, src, dst, port = modified_rule

            proto = 'ANY' if proto == 'all' else proto
            src   = 'ANY' if src == '0.0.0.0/0' else src
            dst   = 'ANY' if dst == '0.0.0.0/0' else dst

            firewallrules.append((pos, src, dst, proto.upper(), port, action))

#        print(firewallrules)
        return firewallrules

    @staticmethod
    def nat_rules(*, nat_type='DSTNAT'):
        natrules = []
        output = run(
            f'sudo iptables -t nat --list-rules | grep "A {nat_type}"', shell=True, capture_output=True, text=True
        ).stdout.splitlines()

        for i, rule in enumerate(output, 1):

            rule, rule_d = rule.split(), {}
            while rule:
                data, rule = rule[:2], rule[2:]

                arg, value = data
                # filtering out unneccesary args
                if arg in ['-m', '-j']: continue

                if (nat_type == 'SRCNAT'):
                    rule_d[arg] = value

                elif (nat_type == 'DSTNAT'):

                    if (arg != '--to-destination'):
                        rule_d[arg] = value

                    else:
                        try:
                            rule_d['--to-port'] = value.split(':')[1]
                            rule_d['--to-dest'] = value.split(':')[0]
                        except IndexError:
                            rule_d['--to-dest'] = value
                            rule_d['--to-port'] = rule_d['--dport']



            natrules.append((i, rule_d))

        # print(natrules)
        return natrules

    @staticmethod
    def ip_whitelist():
        ip_whitelist = {}
        output = run('sudo iptables -nL IP_WHITELIST --line-number', shell=True, capture_output=True, text=True).stdout.splitlines()
        for rule in output:
            rule = rule.split()
            if (not rule[0].isdigit()): continue

            ip_whitelist[rule[0]] = rule[4] # host ip

#        print(ip_whitelist)
        return ip_whitelist

    @staticmethod
    def standard_to_cidr(netmask):
        return {
            '255.255.255.0'  : '24', '255.255.255.128': '25', '255.255.255.192': '26',
            '255.255.255.224': '27', '255.255.255.240': '28', '255.255.255.248': '29',
            '255.255.255.252': '30', '255.255.255.254': '31', '255.255.255.255': '32'
        }[netmask]


class Services:

    @staticmethod
    def status(service):
        try:
            return run(f'sudo systemctl status {service}', shell=True, check=True, stdout=DEVNULL)
        except CalledProcessError:
            return False

    @staticmethod
    def start(service):
        run(f'sudo systemctl start {service}', shell=True, stdout=DEVNULL)

    @staticmethod
    def restart(service):
        run(f'sudo systemctl restart {service}', shell=True, stdout=DEVNULL)

    @staticmethod
    def stop(service):
        run(f'sudo systemctl stop {service}', shell=True, stdout=DEVNULL)
