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
from dnx_routines.configure.system_info import System as _System

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_namedtuples import IPP_EVENT_LOG, DNS_REQUEST_LOG, IPS_EVENT_LOG, GEOLOCATION_LOG
    from dnx_gentools.def_namedtuples import INF_EVENT_LOG


db = _db_conn.DBConnector

# ========================================
# INSERT ROUTINES
# ========================================
@db.register('dns_request', routine_type='write')
# standard input for dns proxy module database entries
def dns_request(cur, timestamp: int, log: DNS_REQUEST_LOG) -> bool:
    cur.execute(
        f'select * from dnsproxy where src_ip=? and domain=? and action=?', (log.src_ip, log.request, log.action)
    )

    existing_record = cur.fetchone()
    if (existing_record):

        i, t = existing_record[5] + 1, existing_record[6]
        if (timestamp - t > 10):
            cur.execute(f'update dnsproxy set count=?, last_seen=?, reason=? where src_ip=? and domain=? and action=?',
                (i, timestamp, log.reason, log.src_ip, log.request, log.action))

    else:
        cur.execute(f'insert into dnsproxy values (?, ?, ?, ?, ?, ?, ?)',
            (log.src_ip, log.request, log.category, log.reason, log.action, 1, timestamp)
        )

    return True

@db.register('dns_blocked', routine_type='write')
# used by dns proxy to authorize front end block page access.
def dns_blocked(cur, timestamp: int, log: DNS_REQUEST_LOG) -> bool:
    cur.execute(
        f'insert into blocked values (?, ?, ?, ?, ?)', (log.src_ip, log.request, log.category, log.reason, timestamp)
    )

    return True

@db.register('ips_event', routine_type='write')
# standard input for ips module database entries
def ips_event(cur, timestamp: int, log: IPS_EVENT_LOG) -> bool:
    cur.execute(f'select * from ips where src_ip=? and attack_type=? order by last_seen desc limit 1',
        (log.attacker, log.attack_type)
    )

    existing_record = cur.fetchone()
    if (existing_record):

        t = existing_record[4]
        if (timestamp - t > 10):
            cur.execute(f'insert into ips values (?, ?, ?, ?, ?)',
                (log.attacker, log.protocol, log.attack_type, log.action, timestamp)
            )

    else:
        cur.execute(f'insert into ips values (?, ?, ?, ?, ?)',
            (log.attacker, log.protocol, log.attack_type, log.action, timestamp)
        )

    return True

@db.register('ipp_event', routine_type='write')
# standard input for ip proxy module database entries.
def ipp_event(cur, timestamp: int, log: IPP_EVENT_LOG) -> bool:
    cur.execute(f'insert into ipproxy values (?, ?, ?, ?, ?, ?)',
        (log.local_ip, log.tracked_ip, '/'.join(log.category), log.direction, log.action, timestamp))

    return True

@db.register('inf_event', routine_type='write')
def infected_event(cur, timestamp: int, log: INF_EVENT_LOG) -> bool:
    cur.execute(f'select * from infectedclients where mac=? and detected_host=?',
        (log.client_mac, log.detected_host)
    )

    existing_record = cur.fetchone()
    if (existing_record):

        cur.execute(f'update infectedclients set last_seen=? where mac=? and detected_host=?',
            (timestamp, log.client_mac, log.detected_host)
        )

    else:
        cur.execute(f'insert into infectedclients values (?, ?, ?, ?, ?)',
            (log.client_mac, log.src_ip, log.detected_host, log.reason, timestamp)
        )

    return True

@db.register('geolocation', routine_type='write')
# first arg is timestamp. this can likely go away with new DB API.
def geo_record(cur, _, log: GEOLOCATION_LOG) -> bool:
    month = ','.join(_System.date()[:2])

    # TODO: can this be switched to if not exists?
    cur.execute(f'select * from geolocation where month=? and country=?', (month, log.country))

    existing_record = cur.fetchone()
    # if first time the country has been seen in the current month, it will be initialized with zeroes
    if (not existing_record):
        cur.execute(f'insert into geolocation values (?, ?, ?, ?, ?)', (month, log.country, log.direction, 0, 0))

    # TODO: what does this mean? this needs to be explained better because it looks fucked up.
    # incremented count of the actions specified in the log.
    cur.execute(f'update geolocation set {log.action}={log.action}+1 where month=? and country=? and direction=?',
        (month, log.country, log.direction)
    )

    return True

# ===============================
# REMOVE / CLEAR ROUTINES
# ===============================
@db.register('clear_infected', routine_type='clear')
# TODO: see why this wasnt being committed. i feel like it was an oversight.
# TODO: also type this
def clear_infected(cur, infected_client, detected_host):
    cur.execute(f'delete from infectedclients where mac=? and detected_host=?', (infected_client, detected_host))

    return True

# ================================
# QUERY ROUTINES
# ================================
@db.register('blocked_domain', routine_type='query')
# query to authorize viewing of web block page and show block info for reference
def blocked_domain(cur, *, domain: str, src_ip: str) -> _BLOCKED_DOM:
    for _ in range(6):
        cur.execute(f'select * from blocked where domain=? and src_ip=?', (domain, src_ip))
        try:
            return _BLOCKED_DOM(*cur.fetchone()[1:4])
        except TypeError:
            _fsleep(.25)

@db.register('last', routine_type='query')
# most recent X matching rows
def last(cur, count: int, src_ip: Optional[str] = None, *, table: str, action: str) -> list:
    if (action in ['allowed', 'blocked']):
        if (src_ip):
            cur.execute(f'select * from {table} where src_ip=? and action=? order by last_seen desc limit {count}',
                (src_ip, action))

        else:
            cur.execute(f'select * from {table} where action=? order by last_seen desc limit {count}', (action,))

    elif (action in ['all']):
        cur.execute(f'select * from {table} order by last_seen desc limit {count}')

    return cur.fetchall()

@db.register('top', routine_type='query')
def top(cur, count: int, *, table: str, action: str) -> list:
    if (action in ['allowed', 'blocked']):
        cur.execute(f'select * from {table} where action=? order by count desc limit {count}', (action,))

    elif (action in ['all']):
        cur.execute(f'select * from {table} order by count desc limit {count}')

    return cur.fetchall()

@db.register('top_dashboard', routine_type='query')
def top_dashboard(cur, count, *, action):
    if (action in ['allowed', 'blocked']):
        cur.execute(
            f'select domain, category, sum(count) from dnsproxy where action=? '
            f'group by domain order by count desc limit {count}',
            (action,)
        )

    elif (action in ['all']):
        cur.execute(
            f'select domain, category, sum(count) from dnsproxy group by domain order by count desc limit {count}'
        )

    return [(x[0], x[1]) for x in cur.fetchall()]

@db.register('top_geolocation', routine_type='query')
def top_geolocation(cur, count: int, *, action: str, direction: str) -> list[str]:
    month = ','.join(_System.date()[:2])

    # table has a separate column for allowed and blocked. this is why we select and sort on the action directly.
    cur.execute(
        f'select country from geolocation where month=? and direction=? and {action} > 0 '
        f'order by {action} desc limit {count}', (month, direction, action)
    )

    # filtering out entries with no hits in the specified action.
    return [x.replace('_', ' ') for x in cur.fetchall()]

@db.register('unique_domain_count', routine_type='query')
# TODO: see if this should use sum() instead of len() on the results
def unique_domain_count(cur, *, action: str) -> int:
    if (action in ['allowed', 'blocked']):
        cur.execute(f'select domain, count(*) from dnsproxy where action=? group by domain', (action,))

    elif (action in ['all']):
        cur.execute(f'select domain, count(*) from dnsproxy group by domain')

    return len(cur.fetchall())

@db.register('total_request_count', routine_type='query')
# TODO: see if this should use sum() instead of iter add
def total_request_count(cur, *, table: str, action: str) -> int:
    if (action in ['allowed', 'blocked']):
        cur.execute(f'select count from {table} where action=?', (action,))

    elif (action in ['all']):
        cur.execute(f'select count from {table}')

    results = cur.fetchall()
    if (not results):
        return 0

    count = 0
    for res in results:
        count += res[0]

    return count

@db.register('malware_count', routine_type='query')
# TODO: see if this should use sum() instead of iter add
def malware_count(cur, *, table: str) -> int:
    cur.execute(f'select * from {table} where action=? and category=? or category=?',
        ('blocked', 'malicious', 'cryptominer'))

    results = cur.fetchall()
    if (not results):
        return 0

    count = 0
    for res in results:
        count += res[0]

    return count
