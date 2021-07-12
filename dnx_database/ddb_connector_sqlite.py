#!/usr/bin/python3

import os, sys
import time
import json
import sqlite3
import datetime
import traceback

from types import SimpleNamespace as SName
from collections import namedtuple

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import SQL_VERSION, ONE_DAY, FIVE_MIN, fast_time, write_log
from dnx_configure.dnx_namedtuples import BLOCKED_DOM

__all__ = ('DBConnector',)


class _DBConnector:
    DB_PATH = f'{HOME_DIR}/dnx_system/data/dnxfirewall.sqlite3'

    # NOTE: if Log is not sent int, calling any method configured to log will error out, but likely not cause
    # significant impact as it is covered by the context.
    def __init__(self, Log=None, *, table=None):
        self._Log = Log

        self._table = table

        self._data_written = False

    def __enter__(self):
        self._conn = sqlite3.connect(self.DB_PATH)
        self._c = self._conn.cursor()

        return self

    def __exit__(self, exc_type, exc_val, traceback):
        if (self._data_written):
            self._conn.commit()

        self._conn.close()

        # This should be logged through the logging system. Worst case use simple log if full logging is not easily in reach.
        if (exc_type):
            self._Log.error(f'error while writing to database: {exc_val}')

        return True

    def commit_entries(self):
        self._conn.commit()

    # standard input for dns proxy module database entries
    def dns_input(self, timestamp, log):

        results = self._dns_entry_check(log.src_ip, log.request, log.action)
        if (not results):
            self._c.execute(f'insert into dnsproxy values (?, ?, ?, ?, ?, ?, ?)',
                (log.src_ip, log.request, log.category, log.reason, log.action, 1, timestamp))

            return

        i, t = results[5] + 1, results[6]
        if (timestamp - t > 10):
            self._c.execute(f'update dnsproxy set count=?, last_seen=?, reason=? where src_ip=? and domain=? and action=?',
                (i, timestamp, log.reason, log.src_ip, log.request, log.action))

        self._data_written = True

    # used only by the standard_input method
    def _dns_entry_check(self, src_ip, request, action):
        self._c.execute(f'select * from dnsproxy where src_ip=? and domain=? and action=?', (src_ip, request, action))

        return self._c.fetchone()

    # used by dns proxy to authorize front end block page access.
    def blocked_input(self, timestamp, log):

        self._c.execute(f'insert into blocked values (?, ?, ?, ?, ?)',
            (log.src_ip, log.request, log.category, log.reason, timestamp))

        self._data_written = True

    # standard input for ips module database entries
    def ips_input(self, timestamp, log):

        results = self._ips_entry_check(log.ip, log.attack_type)
        if (not results):
            self._c.execute(f'insert into ips values (?, ?, ?, ?, ?)',
                (log.ip, log.protocol, log.attack_type, log.action, timestamp))

            return

        t = results[4]
        if (timestamp - t > 10):
            self._c.execute(f'insert into ips values (?, ?, ?, ?, ?)',
                (log.ip, log.protocol, log.attack_type, log.action, timestamp))

        self._data_written = True

    # used only by the ips_input method
    def _ips_entry_check(self, src_ip, attack_type):
        self._c.execute(f'select * from ips where src_ip=? and attack_type=? order by last_seen desc limit 1', (src_ip, attack_type))

        return self._c.fetchone()

    # standard input for ip proxy module database entries. Supression built in to IP Proxy (will not log duplicate host until 30 timeout)
    def ipp_input(self, timestamp, log):

        self._c.execute(f'insert into ipproxy values (?, ?, ?, ?, ?, ?)',
            (log.local_ip, log.tracked_ip, log.category, log.direction, log.action, timestamp))

        self._data_written = True

    def infected_input(self, timestamp, log):

        results = self._infected_entry_check(log.infected_client, log.detected_host)
        if (not results):
            self._c.execute(f'insert into infectedclients values (?, ?, ?, ?, ?)',
                (log.infected_client, log.src_ip, log.detected_host, log.reason, timestamp))

        else:
            self._c.execute(f'update infectedclients set last_seen=? where mac=? and detected_host=?',
                (timestamp, log.infected_client, log.detected_host))

        self._data_written = True

    def _infected_entry_check(self, infected_client, detected_host):
        self._c.execute(f'select * from infectedclients where mac=? and detected_host=?', (infected_client, detected_host))

        return self._c.fetchone()

    def infected_remove(self, infected_client, detected_host, *, table):
        self._c.execute(f'delete from {table} where mac=? and detected_host=?', (infected_client, detected_host))

    # query to authorize viewing of web block page and show block info for reference
    def query_blocked(self, *, domain, src_ip):

        for _ in range(5):
            self._c.execute(f'select * from blocked where domain=? and src_ip=?', (domain, src_ip))
            try:
                return BLOCKED_DOM(*self._c.fetchone()[1:4])
            except TypeError:
                time.sleep(1)

        # NOTE: log this to front end using simple log and make the error more useful.
        else:
            write_log(f'blocked query lookup error: {domain} from {src_ip} !!')

    def query_last(self, count, src_ip=None, *, table, action):
        if (action in ['allowed', 'blocked']):
            if (src_ip):
                self._c.execute(f'select * from {table} where src_ip=? and action=? order by last_seen desc limit {count}', (src_ip, action))

            else:
                self._c.execute(f'select * from {table} where action=? order by last_seen desc limit {count}', (action,))

        elif (action in ['all']):
            self._c.execute(f'select * from {table} order by last_seen desc limit {count}')

        return self._c.fetchall()

    def query_top(self, count, *, table, action):
        if (action in ['allowed', 'blocked']):
            self._c.execute(f'select * from {table} where action=? order by count desc limit {count}', (action,))

        elif (action in ['all']):
            self._c.execute(f'select * from {table} order by count desc limit {count}')

        return self._c.fetchall()

    def dashboard_query_top(self, count, *, table, action):
        if (action in ['allowed', 'blocked']):
            self._c.execute(f'select * from {table} where action=? order by count desc limit 20', (action,))

        elif (action in ['all']):
            self._c.execute(f'select * from {table} order by count desc limit 20')
        results = self._c.fetchall()

        top_domains = {}
        for result in results:

            _, domain, category, *_ = result
            if (domain not in top_domains):

                if (len(domain) > 41):
                    domain = domain[:41]

                top_domains[domain] = category

            if (len(top_domains) == count): break

        return top_domains

    def unique_domain_count(self, *, table, action):
        unique_domains = set()

        if (action in ['allow', 'blocked']):
            self._c.execute(f'select * from {table} where action=?', (action,))

        elif (action in ['all']):
            self._c.execute(f'select * from {table}')

        results = self._c.fetchall()
        if (not results): return 0

        for entry in results:
            domain = entry[1]
            unique_domains.add(domain)

        return len(unique_domains)

    def total_request_count(self, *, table, action):
        if (action in ['allow', 'blocked']):
            self._c.execute(f'select count from {table} where action=?', (action,))

        elif (action in ['all']):
            self._c.execute(f'select count from {table}')

        results = self._c.fetchall()
        if (not results): return 0

        request_count = 0
        for res in results:
            request_count += res[0]

        return request_count

    def malware_count(self, *, table):
        self._c.execute(f'select * from {table} where action=? and category=? or category=?',
            ('blocked', 'malicious', 'cryptominer'))

        results = self._c.fetchall()
        if (not results): return 0

        malware_count = 0
        for res in results:
            malware_count += res[0]

        return malware_count

    def blocked_cleaner(self, table):
        expire_threshold = int(fast_time()) - FIVE_MIN
        self._c.execute(f'delete from {table} where timestamp < {expire_threshold}')

        self._data_written = True

    def table_cleaner(self, log_length, table):
        expire_threshold = int(fast_time()) - (ONE_DAY * log_length)
        self._c.execute(f'delete from {table} where last_seen < {expire_threshold}')

        self._data_written = True

    def create_db_tables(self):
        self._c.execute(
            'create table if not exists dnsproxy '
            '(src_ip text not null, domain text not null, '
            'category text not null, reason text not null, '
            'action text not null, count int4 not null, '
            'last_seen int4 not null)'
        )

        self._c.execute(
            'create table if not exists infectedclients '
            '(mac text not null, ip_address text not null, '
            'detected_host text not null, reason text not null, '
            'last_seen int4 not null)'
        )

        self._c.execute(
            'create table if not exists ipproxy '
            '(local_ip text not null, tracked_ip text not null, '
            'category text not null, direction text not null, '
            'action text not null, last_seen int4 not null)'
        )

        self._c.execute(
            'create table if not exists ips '
            '(src_ip not null, protocol not null, '
            'attack_type not null, action not null, '
            'last_seen not null)'
        )

        self._c.execute(
            'create table if not exists blocked '
            '(src_ip not null, domain not null, '
            'category not null, reason not null, '
            'timestamp not null)'
        )

if (SQL_VERSION == 1):
    from dnx_database.ddb_connector_psql import DBConnector

else:
    DBConnector = _DBConnector

if __name__ == '__main__':
    # NOTE: CREATE THE TABLES
    #   only used on self deployments where system is running already and the tables need to be created
    with DBConnector() as FirewallDB:
        FirewallDB.create_db_tables()
