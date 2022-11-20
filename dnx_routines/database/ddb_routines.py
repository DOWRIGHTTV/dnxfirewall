#!/usr/bin/env python3

from __future__ import annotations

# ================================================
# DATABASE ROUTINES REFERENCED BY CONNECTOR CLASS
#
# current standard:
#   all routines must accept database cursor obj
#   as their first argument
#
#   all routines must be registered with the
#   database connector @register specifying name
#   and routine type as decorator arguments
#
#   all writing routines must return boolean of
#   whether data was successfully written
#
#   all reading routing must return a single var
#   this can be list, dict, int, bool, etc. since
#   it will be passed through connector without
#   accessing the data.

import dnx_routines.database.ddb_connector_sqlite as _db_conn

from dnx_gentools.def_typing import TYPE_CHECKING, Optional
from dnx_gentools.def_constants import fast_sleep as _fsleep
from dnx_gentools.def_namedtuples import BLOCKED_DOM as _BLOCKED_DOM
from dnx_gentools.system_info import System as _System

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_namedtuples import IPP_EVENT_LOG, DNS_REQUEST_LOG, IPS_EVENT_LOG, GEOLOCATION_LOG
    from dnx_gentools.def_namedtuples import INF_EVENT_LOG, SECURE_MESSAGE

    from sqlite3 import Cursor


db = _db_conn.DBConnector

# ========================================
# INSERT ROUTINES
# ========================================
@db.register('dns_request', routine_type='write')
# standard input for dns proxy module database entries
def dns_request(cur: Cursor, timestamp: int, log: DNS_REQUEST_LOG) -> bool:
    cur.execute(
        f'select * from dnsproxy where src_ip=? and domain=? and action=?', (log.src_ip, log.request, log.action)
    )

    existing_record = cur.fetchone()
    if (existing_record):

        i, t = existing_record[5] + 1, existing_record[6]
        if (timestamp - t > 10):
            cur.execute(
                f'update dnsproxy set count=?, last_seen=?, reason=? where src_ip=? and domain=? and action=?',
                (i, timestamp, log.reason, log.src_ip, log.request, log.action)
            )

    else:
        cur.execute(
            f'insert into dnsproxy values (?, ?, ?, ?, ?, ?, ?)',
            (log.src_ip, log.request, log.category, log.reason, log.action, 1, timestamp)
        )

    return True

@db.register('dns_blocked', routine_type='write')
# used by dns proxy to authorize front end block page access.
def dns_blocked(cur: Cursor, timestamp: int, log: DNS_REQUEST_LOG) -> bool:
    cur.execute(
        f'insert into blocked values (?, ?, ?, ?, ?)', (log.src_ip, log.request, log.category, log.reason, timestamp)
    )

    return True

@db.register('ips_event', routine_type='write')
# standard input for ips module database entries
def ips_event(cur: Cursor, timestamp: int, log: IPS_EVENT_LOG) -> bool:
    cur.execute(
        f'select * from ips where src_ip=? and attack_type=? order by last_seen desc limit 1', (log.attacker, log.attack_type)
    )

    existing_record = cur.fetchone()
    if (existing_record):

        t = existing_record[4]
        if (timestamp - t > 10):
            cur.execute(
                f'insert into ips values (?, ?, ?, ?, ?)',
                (log.attacker, log.protocol, log.attack_type, log.action, timestamp)
            )

    else:
        cur.execute(
            f'insert into ips values (?, ?, ?, ?, ?)',
            (log.attacker, log.protocol, log.attack_type, log.action, timestamp)
        )

    return True

@db.register('ipp_event', routine_type='write')
# standard input for ip proxy module database entries.
def ipp_event(cur: Cursor, timestamp: int, log: IPP_EVENT_LOG) -> bool:
    cur.execute(
        f'insert into ipproxy values (?, ?, ?, ?, ?, ?)',
        (log.local_ip, log.tracked_ip, '/'.join(log.category), log.direction, log.action, timestamp)
    )

    return True

@db.register('inf_event', routine_type='write')
def infected_event(cur: Cursor, timestamp: int, log: INF_EVENT_LOG) -> bool:
    cur.execute(f'select * from infectedclients where mac=? and detected_host=?', (log.client_mac, log.detected_host))

    existing_record = cur.fetchone()
    if (existing_record):

        cur.execute(
            f'update infectedclients set last_seen=? where mac=? and detected_host=?',
            (timestamp, log.client_mac, log.detected_host)
        )

    else:
        cur.execute(
            f'insert into infectedclients values (?, ?, ?, ?, ?)',
            (log.client_mac, log.src_ip, log.detected_host, log.reason, timestamp)
        )

    return True

@db.register('geolocation', routine_type='write')
# first arg is timestamp. this can likely go away with new DB API.
def geo_record(cur: Cursor, _, log: GEOLOCATION_LOG) -> bool:
    month = ','.join(_System.date()[:2])

    # TODO: can this be switched to if not exists?
    cur.execute(f'select * from geolocation where month=? and country=?', (month, log.country))

    existing_record = cur.fetchone()
    # if it's the first time a country has been seen in the current month, it will be initialized with zeroes
    if (not existing_record):
        cur.execute(f'insert into geolocation values (?, ?, ?, ?, ?)', (month, log.country, log.direction, 0, 0))

    # TODO: what does this mean? this needs to be explained better because it looks fucked up.
    # incremented count of the actions specified in the log.
    cur.execute(
        f'update geolocation set {log.action}={log.action}+1 where month=? and country=? and direction=?',
        (month, log.country, log.direction)
    )

    return True

@db.register('send_message', routine_type='write')
def send_message(cur: Cursor, message: SECURE_MESSAGE) -> bool:
    cur.execute('insert into messenger values (?, ?, ?, ?, ?, ?)', message)

    return True

# ===============================
# REMOVE / CLEAR ROUTINES
# ===============================
@db.register('clear_infected', routine_type='clear')
# TODO: see why this wasnt being committed. i feel like it was an oversight.
# TODO: also type this
def clear_infected(cur: Cursor, infected_client, detected_host):
    cur.execute(f'delete from infectedclients where mac=? and detected_host=?', (infected_client, detected_host))

    return True

# ================================
# QUERY ROUTINES
# ================================
@db.register('blocked_domain', routine_type='query')
# query to authorize viewing of web block page and show block info for reference
def blocked_domain(cur: Cursor, *, domain: str, src_ip: str) -> _BLOCKED_DOM:
    for _ in range(6):
        cur.execute(f'select * from blocked where domain=? and src_ip=?', (domain, src_ip))
        try:
            return _BLOCKED_DOM(*cur.fetchone()[1:4])
        except TypeError:
            _fsleep(.25)

@db.register('last', routine_type='query')
# most recent X matching rows
def last(cur: Cursor, count: int, src_ip: Optional[str] = None, *, table: str, action: str) -> list:
    if (action in ['all']):
        cur.execute(f'select * from {table} order by last_seen desc limit {count}')

    elif (action in ['allowed', 'blocked']):
        if (not src_ip):
            cur.execute(f'select * from {table} where action=? order by last_seen desc limit {count}', (action,))
        else:
            cur.execute(
                f'select * from {table} where src_ip=? and action=? order by last_seen desc limit {count}', (src_ip, action)
            )

    return cur.fetchall()

@db.register('top', routine_type='query')
def top(cur: Cursor, count: int, *, table: str, action: str) -> list:
    if (action in ['all']):
        cur.execute(f'select * from {table} order by count desc limit {count}')

    elif (action in ['allowed', 'blocked']):
        cur.execute(f'select * from {table} where action=? order by count desc limit {count}', (action,))

    return cur.fetchall()

@db.register('top_dashboard', routine_type='query')
def top_dashboard(cur: Cursor, count, *, action):
    if (action in ['all']):
        cur.execute(f'select domain, category, sum(count) from dnsproxy group by domain order by count desc limit {count}')

    elif (action in ['allowed', 'blocked']):
        cur.execute(
            f'select domain, category, sum(count) from dnsproxy where action=? '
            f'group by domain order by count desc limit {count}',
            (action,)
        )

    return [(x[0], x[1]) for x in cur.fetchall()]

@db.register('top_geolocation', routine_type='query')
def top_geolocation(cur: Cursor, count: int, *, action: str, direction: str) -> list[str]:
    month = ','.join(_System.date()[:2])

    # table has a separate column for allowed and blocked. this is why we select and sort on the action directly.
    cur.execute(
        f'select country from geolocation where month=? and direction=? and {action} > 0 '
        f'order by {action} desc limit {count}', (month, direction)
    )

    # filtering out entries with no hits in the specified action.
    return [x.replace('_', ' ') for x in cur.fetchall()]

@db.register('unique_domain_count', routine_type='query')
# TODO: see if this should use sum() instead of len() on the results
def unique_domain_count(cur: Cursor, *, action: str) -> int:
    if (action in ['all']):
        cur.execute(f'select domain, count(*) from dnsproxy group by domain')

    elif (action in ['allowed', 'blocked']):
        cur.execute(f'select domain, count(*) from dnsproxy where action=? group by domain', (action,))

    return len(cur.fetchall())

@db.register('total_request_count', routine_type='query')
# TODO: see if this should use sum() instead of iter add
def total_request_count(cur: Cursor, *, table: str, action: str) -> int:
    if (action in ['all']):
        cur.execute(f'select count from {table}')

    elif (action in ['allowed', 'blocked']):
        cur.execute(f'select count from {table} where action=?', (action,))

    results = cur.fetchall()
    if (not results):
        return 0

    count = 0
    for res in results:
        count += res[0]

    return count

@db.register('malware_count', routine_type='query')
# TODO: see if this should use sum() instead of iter add
def malware_count(cur: Cursor, *, table: str) -> int:
    cur.execute(
        f'select * from {table} where action=? and category=? or category=?', ('blocked', 'malicious', 'cryptominer')
    )

    results = cur.fetchall()
    if (not results):
        return 0

    count = 0
    for res in results:
        count += res[0]

    return count

@db.register('get_messages', routine_type='query')
def get_messages(cur: Cursor, *, sender: str, recipients: str) -> list:
    cur.execute(
        'select * from messenger where sender=? and recipients=? order by sent_at', (sender, recipients)
    )

    return cur.fetchall()
