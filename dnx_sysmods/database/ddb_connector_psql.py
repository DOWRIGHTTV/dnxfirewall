#!/usr/bin/python3

import os, sys
import time
import datetime
import traceback

from types import SimpleNamespace as SName
from collections import namedtuple

HOME_DIR = os.environ.get('HOME_DIR', os.path.dirname(os.path.dirname((os.path.realpath('__file__')))))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import ONE_DAY, FIVE_MIN, write_log, fast_time
from dnx_sysmods.configure.def_namedtuples import BLOCKED_DOM

USER = 'dnx'
PASSWORD = 'firewall'

try:
    import pg8000
except:
    raise RuntimeError('pg8000 library is required if running in postgresql mode.')


# TODO: make sure the fixes done to sqlite connector are translated to this module as well.
class DBConnector:
    def __init__(self, Log=None, *, table=None):
        self.table = table

        self.data_written = False

    def __enter__(self):
        self.conn = pg8000.connect(database='dnxfirewall', user=USER, password=PASSWORD, host='127.0.0.1', port=5432)
        self.c = self.conn.cursor()

        return self

    def __exit__(self, exc_type, exc_val, traceback):
        if (self.data_written):
            self.conn.commit()
        self.conn.close()

        return True

    def commit_entries(self):
        self.conn.commit()

    # standard input for dns proxy module database entries
    def dns_input(self, timestamp, log):
        table = 'dnsproxy'
        results = self._dns_entry_check(log.src_ip, log.request, log.action)
        if (not results):
            self.c.execute(f'insert into {table} values (%s, %s, %s, %s, %s, %s, %s)',
                (log.src_ip, log.request, log.category, log.reason, log.action, 1, timestamp))
            return

        i, t = results[5] + 1, results[6]
        if (timestamp - t > 10):
            self.c.execute(f'update {table} set count=%s, last_seen=%s, reason=%s where src_ip=%s and domain=%s and action=%s',
                (i, timestamp, log.reason, log.src_ip, log.request, log.action))
        self.data_written = True

    # used only by the standard_input method
    def _dns_entry_check(self, src_ip, request, action):
        self.c.execute(f'select * from dnsproxy where src_ip=%s and domain=%s and action=%s', (src_ip, request, action))

        return self.c.fetchone()

    # used by dns proxy to authorize front end block page access.
    def blocked_input(self, timestamp, log):
        table = 'blocked'
        self.c.execute(f'insert into {table} values (%s, %s, %s, %s, %s)',
            (log.src_ip, log.request, log.category, log.reason, timestamp))
        self.data_written = True

    # standard input for ips module database entries
    def ips_input(self, timestamp, log):
        table = 'ips'
        results = self._ips_entry_check(log.ip, log.attack_type)
        if (not results):
            self.c.execute(f'insert into {table} values (%s, %s, %s, %s, %s)',
                (log.ip, log.protocol, log.attack_type, log.action, timestamp))
            return

        t = results[4]
        if (timestamp - t > 10):
            self.c.execute(f'insert into {table} values (%s, %s, %s, %s, %s)',
                (log.ip, log.protocol, log.attack_type, log.action, timestamp))
        self.data_written = True

    # used only by the ips_input method
    def _ips_entry_check(self, src_ip, attack_type):
        self.c.execute(f'select * from ips where src_ip=%s and attack_type=%s order by last_seen desc limit 1', (src_ip, attack_type))

        return self.c.fetchone()

    # standard input for ip proxy module database entries. Supression built in to IP Proxy (will not log duplicate host until 30 timeout)
    def ipp_input(self, timestamp, log):
        table = 'ipproxy'
        self.c.execute(f'insert into {table} values (%s, %s, %s, %s, %s, %s)',
            (log.local_ip, log.tracked_ip, log.category, log.direction, log.action, timestamp))
        self.data_written = True

    def infected_input(self, timestamp, log):
        table = 'infectedclients'
        results = self._infected_entry_check(table, log.infected_client, log.detected_host)
        if (not results):
            self.c.execute(f'insert into {table} values (%s, %s, %s, %s, %s)',
                (log.infected_client, log.src_ip, log.detected_host, log.reason, timestamp))
        else:
            self.c.execute(f'update {table} set last_seen=%s where mac=%s and detected_host=%s',
                (timestamp, log.infected_client, log.detected_host))
        self.data_written = True

    def _infected_entry_check(self, table, infected_client, detected_host):
        self.c.execute(f'select * from {table} where mac=%s and detected_host=%s', (infected_client, detected_host))

        return self.c.fetchone()

    def infected_remove(self, infected_client, detected_host, *, table):
        self.c.execute(f'delete from {table} where mac=%s and detected_host=%s', (infected_client, detected_host))

    # query to authorize viewing of web block page and show block info for reference
    def query_blocked(self, *, domain, src_ip):
        table = 'blocked'
        for _ in range(5):
            self.c.execute(f'select * from {table} where domain=%s and src_ip=%s', (domain, src_ip))
            try:
                return BLOCKED_DOM(*self.c.fetchone()[1:4])
            except TypeError:
                time.sleep(1)
        # NOTE: log this to front end
        else:
            write_log('BLOCKED QUERY LOOKUP ERROR!!')

    def query_last(self, count, src_ip=None, *, table, action):
        if (action in ['allowed', 'blocked']):
            if (src_ip):
                self.c.execute(f'select * from {table} where src_ip=%s and action=%s order by last_seen desc limit {count}', (src_ip, action))
            else:
                self.c.execute(f'select * from {table} where action=%s order by last_seen desc limit {count}', (action,))
        elif (action in ['all']):
            self.c.execute(f'select * from {table} order by last_seen desc limit {count}')

        return self.c.fetchall()

    def query_top(self, count, *, table, action):
        if (action in ['allowed', 'blocked']):
            self.c.execute(f'select * from {table} where action=%s order by count desc limit {count}', (action,))
        elif (action in ['all']):
            self.c.execute(f'select * from {table} order by count desc limit {count}')

        return self.c.fetchall()

    def dashboard_query_top(self, count, *, action):
        if (action in ['allowed', 'blocked']):
            self.c.execute(
                f'select domain, category from dnsproxy where action=? group by domain order by count(*) desc limit {count}', (action,)
            )

        elif (action in ['all']):
            self.c.execute(f'select domain, category from dnsproxy group by domain order by count(*) desc limit {count}')

        return self.c.fetchall()[:count]

    def query_geolocation(self, count, *, action, direction):
        lim = count + 5 # this will ensure there is always room even if results contain elements that will be filtered
        if (action in ['allow', 'blocked']):
            self.c.execute(
                f'select category from ipproxy where action=? and direction=? group by category order by count(*) desc limit {lim}',
                (action, direction)
            )

        elif (action in ['all']):
            self.c.execute(
                f'select category from ipproxy where direction=? group by category order by count(*) desc limit {lim}', (direction,)
            )

        results = self.c.fetchall()

        # get correct tor category names. i cant remember them off top since it recently changed.
        return [x for x in results if x.lower() not in ['malicious', 'compromised', 'tor']][:count]

    def unique_domain_count(self, *, action):
        if (action in ['allow', 'blocked']):
            self.c.execute(f'select domain, count(*) from dnsproxy where action=? group by domain', (action,))

        elif (action in ['all']):
            self.c.execute(f'select domain, count(*) from dnsproxy group by domain')

        return len(self.c.fetchall())

    def total_request_count(self, *, table, action):
        if (action in ['allow', 'blocked']):
            self.c.execute(f'select count from {table} where action=%s', (action,))
        elif (action in ['all']):
            self.c.execute(f'select count from {table}')

        results = self.c.fetchall()
        if (not results): return 0

        request_count = 0
        for res in results:
            request_count += res[0]

        return request_count

    def malware_count(self, *, table):
        self.c.execute(f'select * from {table} where action=%s and category=%s or category=%s',
            ('blocked', 'malicious', 'cryptominer'))
        results = self.c.fetchall()
        if (not results): return 0

        malware_count = 0
        for res in results:
            malware_count += res[0]

        return malware_count

    def blocked_cleaner(self, table):
        expire_threshold = int(fast_time()) - FIVE_MIN
        self.c.execute(f'delete from {table} where timestamp < {expire_threshold}')

        self.data_written = True

    def table_cleaner(self, log_length, table):
        expire_threshold = int(fast_time()) - (ONE_DAY * log_length)
        self.c.execute(f'delete from {table} where last_seen < {expire_threshold}')

        self.data_written = True

    def create_db_tables(self):
        self.c.execute('create table if not exists dnsproxy \
                        (src_ip text not null, domain text not null, \
                        category text not null, reason text not null, \
                        action text not null, count int4 not null, \
                        last_seen int4 not null)')

        self.c.execute('create table if not exists infectedclients \
                        (mac text not null, ip_address text not null, \
                        detected_host text not null, reason text not null, \
                        last_seen int4 not null)')

        self.c.execute('create table if not exists ipproxy \
                        (local_ip text not null, tracked_ip text not null, \
                        category text not null, direction text not null, \
                        action text not null, last_seen int4 not null)')

        self.c.execute('create table if not exists ips \
                        (src_ip text not null, protocol text not null, \
                        attack_type text not null, action text not null, \
                        last_seen int4 not null)')

        self.c.execute('create table if not exists blocked \
                        (src_ip text not null, domain text not null, \
                        category text not null, reason text not null, \
                        timestamp int4 not null)')

if __name__ == '__main__':
    ## CREATE THE TABLES
    with DBConnector() as FirewallDB:
        FirewallDB.create_db_tables()

#    table = 'DNSProxy'
#    table = 'PIHosts'
#    table = 'ipproxy'
#    table = 'PIHosts'
    # ProxyDB = DBConnector(table)
    # ProxyDB.Connect()
