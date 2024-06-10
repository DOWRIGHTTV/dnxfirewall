#!/usr/bin/env python3

from __future__ import annotations

import os
import datetime

from time import ctime
from functools import partial
from datetime import datetime, timedelta
from typing import NamedTuple
from subprocess import run, CalledProcessError, DEVNULL

from dnx_gentools.def_constants import module_import_callout

module_import_callout(__file__)

from dnx_gentools.def_constants import TYPE_CHECKING, HOME_DIR, fast_time, str_join, NO_DELAY, ONE_HOUR
from dnx_gentools.file_operations import load_configuration, load_data

# note: prior to system install, this will not be available.
try:
    from dnx_iptools.cprotocol_tools import iptoi
except ImportError:
    pass

if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Union, Optional
    from dnx_gentools.def_typing import ConfigChain

    Timestamp = Union[int, float]


__all__ = (
    'Interface', 'System', 'Services'
)

util_shell = partial(run, shell=True, capture_output=True, text=True)

class DiskStats(NamedTuple):
    size: tuple[float, float]
    used: tuple[float, float]
    log:  tuple[float, float]


class Interface:
    '''This class is being deprecated and being replaced by the interface ops module in iptools dir.
    '''
    @staticmethod
    def bandwidth():
        intstat = {}
        interface_bandwidth = load_data('interface.stat', cfg_type='system/global')
        for interface, value in interface_bandwidth.items():
            rx = str(round(int(value[0])/1024, 2)) + ' MB/s'
            tx = str(round(int(value[1])/1024, 2)) + ' MB/s'
            intstat[interface] = [rx, tx]
#        print(intstat)
        return intstat


class System:

    @staticmethod
    def uptime() -> str:
        with open('/proc/uptime', 'r') as f:
            ut = timedelta(seconds=float(f.read().split()[0]))

        ttl_minutes = ut.seconds // 60

        hours = ttl_minutes // 60
        minutes = ttl_minutes % 60

        return f'days: {ut.days}, hours: {hours}, minutes: {minutes}'

    @staticmethod
    def cpu_usage() -> float:
        '''returns cpu usage as a percentage represented by a float. 69.82
        '''
        with open('/proc/stat', 'r') as cpu:
            line = cpu.readline().split()

        idle = int(line[4])
        total = sum([int(x) for x in line[1:]])

        usage = round(100 - ((idle / total) * 100), 2)

        return usage

    @staticmethod
    def ram_usage() -> float:
        '''returns ram usage as a percentage represented by a float. 69.82
        '''
        total, available = None, None
        with open('/proc/meminfo', 'r') as memory:
            for line in memory:
                if ('MemTotal' in line):
                    total = int(line.split()[1])

                elif ('MemAvailable' in line):
                    available = int(line.split()[1])

                if (total and available): break

        ram = round((total / available) * 10, 1)
#        print(ram)
        return ram

    @staticmethod
    def disk_usage(folder_path: str) -> DiskStats:
        '''Get the total disk size, disk space remaining, and disk space taken by the specified folder.

        returns NamedTuple: DiskStats((GB, %), (GB, %), (GB, %))
        '''
        # Get the total disk space
        disk_stats = os.statvfs('/')

        total_disk_size_GB = round((disk_stats.f_blocks * disk_stats.f_frsize) / (1024 * 1024 * 1024), 2)

        # Get the disk space remaining | calculate used
        disk_space_free_GB = round((disk_stats.f_bfree * disk_stats.f_frsize) / (1024 * 1024 * 1024), 2)

        disk_space_used_GB = round(total_disk_size_GB - disk_space_free_GB, 2)
        disk_space_used_perc = round(disk_space_used_GB / total_disk_size_GB, 4) * 100

        # Get the disk space taken by the folder
        folder_size = 0
        for dirpath, dirnames, filenames in os.walk(folder_path):

            # print(dirpath, dirnames, filenames)

            for f in filenames:

                if (f == 'temp'): continue

                fp = os.path.join(dirpath, f)

                # print(f'checking size of {fp}.')

                folder_size += os.path.getsize(fp)

        folder_size_GB = round(folder_size / (1024 * 1024 * 1024), 2)
        folder_size_perc = round(folder_size_GB / total_disk_size_GB, 4) * 100

        return DiskStats(
            (total_disk_size_GB, 100.0), (disk_space_used_GB, disk_space_used_perc), (folder_size_GB, folder_size_perc)
        )

    @staticmethod
    def offset_and_format(logged_time: Timestamp) -> str:
        '''convenience wrapper around System.calculate_time_offset and System.format_date_time.

            System.format_date_time(System.calculate_time_offset(logged_time))
        '''
        return System.format_date_time(System.calculate_time_offset(logged_time))

    @staticmethod
    # TODO: this is really noisy on disk io. see about doing a basic caching function or allow for optional offset to
    #  be passed in by named arg.
    def calculate_time_offset(logged_time: Timestamp) -> Timestamp:
        '''returns modified time based on current time offset settings.
        '''
        log_settings = load_configuration('logging_client', cfg_type='global')

        os_dir = log_settings['time_offset->direction']
        os_amt = log_settings['time_offset->amount']

        offset = int(f'{os_dir}{os_amt}') * ONE_HOUR

        return logged_time + offset

    @staticmethod
    def format_msg_time(epoch: Timestamp) -> str:
        '''return date and time in the messenger format.

        Jun 24 19:08:15
        '''
        f_time = ctime(epoch).split()

        return f'{f_time[1]} {f_time[2]} {f_time[3]}'

    @staticmethod
    def format_log_time(epoch: Timestamp) -> str:
        '''return date and time in the front end log format.

        2019 Jun 24 19:08:15
        '''
        f_time = ctime(epoch).split()

        return f'{f_time[4]} {f_time[1]} {f_time[2]} {f_time[3]}'

    @staticmethod
    def format_date_time(epoch: Timestamp) -> str:
        '''return date and time in the general format.

        19:08:15 Jun 24 2019
        '''
        f_time = ctime(epoch).split()

        return f'{f_time[3]} {f_time[1]} {f_time[2]} {f_time[4]}'

    @staticmethod
    def format_time(epoch: Timestamp) -> str:
        '''return time in the general 24h format.

        19:08:15
        '''
        return f'{ctime(epoch).split()[3]}'

    @staticmethod
    def date(timestamp: Optional[Timestamp] = None, string: bool = False) -> Union[str, list[str, str, str]]:
        '''return list of year, month, day of current system time as a list of strings.

            ['2019', '06', '24']

        use timestamp argument to override the current date with date of timestamp.

        setting string=True will return a joined list.
        '''
        dt = datetime.now()
        if (timestamp):
            dt = datetime.fromtimestamp(timestamp)

        dt_list = [f'{dt.year}', f'{dt.month:02}', f'{dt.day:02}']
        if (string):
            return str_join(dt_list)

        return dt_list

    @staticmethod
    def time() -> list[int, int]:
        time = datetime.now()

        return [time.hour, time.minute]

    @staticmethod
    def dns_status() -> dict:
        dns_servers_status: dict = load_data('dns_server.stat', cfg_type='usr/global')
        dns_server_cfg: ConfigChain = load_configuration('dns_server', cfg_type='global')

        tls_enabled  = dns_server_cfg['tls->enabled']
        udp_fallback = dns_server_cfg['tls->fallback']

        dns_servers = {}
        for server, info in dns_server_cfg.get_items('resolvers'):
            tls, udp = 'Waiting', 'Waiting'

            active_server = dns_servers_status.get(server, None)
            if (active_server['ip_address'] == info['ip_address']):
                udp = 'UP' if active_server['17'] else 'Down'
                tls = 'Up' if active_server['853'] else 'Down'

            if (not tls_enabled):
                tls = 'Disabled'

            elif (not udp_fallback):
                udp = 'Disabled'

            dns_servers[server] = {
                'name': info['name'],
                'ip_address': info['ip_address'],
                'udp': udp,
                'tls': tls
            }

        return dns_servers

    @staticmethod
    def backups() -> dict[str, float]:
        backups = {}
        backup_dir = f'{HOME_DIR}/dnx_profile/config_backups'
        files = os.listdir(backup_dir)
        for file in files:
            name = file.replace('.tar', '')
            creation_time = os.stat(f'{backup_dir}/{file}').st_ctime  # this is not accurate

            backups[name] = creation_time

#        print(backups)
        return backups

    @staticmethod
    def ips_passively_blocked(
            *, table: str = 'raw', profile_idx: int = 0, block_length: int = NO_DELAY) -> list[tuple[int, int, int]]:
        '''return list of currently blocked hosts in the specific iptables table.

        the default table is 'raw'.

        if profile_idx is defined, only rules within the matching profile will be returned.
        profile_idx of 0 will return all rules.

        if block_length is defined, only hosts that have reached the point of expiration will be returned.
        block_length is an integer value in seconds that represents the length of time a host will be blocked.

            blocked_hosts = System.ips_passivley_blocked(block_length=100)
        '''
        current_time = fast_time()

        # ACCEPT all -- 8.8.8.8(src) 0.0.0.0/0(dst) /* 123456 */L
        host_list = []
        output = util_shell(f'sudo iptables -t {table} -nL IPS').stdout.splitlines()
        for line in output[2:]:
            line = line.split()

            blocked_host, comment = iptoi(line[3]), line[6]

            profile, timestamp = (int(x) for x in comment.split('-'))
            if (profile != profile_idx and profile_idx != 0):
                continue

            # check whether the host rule has reach point of expiration. if not, loop will continue. for NO_DELAY
            # this condition will eval to False immediately, which marks rule for deletion.
            if (timestamp + block_length > current_time):
                continue

            host_list.append((blocked_host, profile, timestamp))

        return host_list

    @staticmethod
    def nat_rules(*, nat_type: str = 'DSTNAT') -> list[tuple[int, dict]]:
        nat_rules = []
        output = util_shell(f'sudo iptables -t nat --list-rules | grep "A {nat_type}"').stdout.splitlines()

        for i, rule in enumerate(output, 1):

            rule, rule_d = rule.split(), {}
            while rule:
                data, rule = rule[:2], rule[2:]

                arg, value = data
                # filtering out unnecessary args
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

            nat_rules.append((i, rule_d))

        # print(nat_rules)
        return nat_rules

    @staticmethod
    def ip_whitelist() -> dict[str, str]:
        ip_whitelist = {}
        output = util_shell('sudo iptables -nL IP_WHITELIST --line-number').stdout.splitlines()
        for rule in output:
            rule = rule.split()
            if (not rule[0].isdigit()): continue

            ip_whitelist[rule[0]] = rule[4]  # host ip

#        print(ip_whitelist)
        return ip_whitelist


_svc_shell = partial(run, shell=True, stdout=DEVNULL)

class Services:

    @staticmethod
    def status(service: str) -> bool:
        try:
            _svc_shell(f'sudo systemctl status {service}', check=True)
        except CalledProcessError:
            return False
        else:
            return True

    @staticmethod
    def start(service: str) -> None:
        _svc_shell(f'sudo systemctl start {service}')

    @staticmethod
    def restart(service: str) -> None:
        _svc_shell(f'sudo systemctl restart {service}')

    @staticmethod
    def stop(service: str) -> None:
        _svc_shell(f'sudo systemctl stop {service}')
