#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_constants import module_import_callout

module_import_callout(__file__)

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
#   all reading routines must return a single var.
#   this can be list, dict, int, bool, etc. since
#   it will be passed through connector without
#   accessing the data.

import dnx_routines.database.ddb_connector_sqlite as _db_conn

from dnx_gentools.def_constants import TYPE_CHECKING, fast_sleep as _fsleep
from dnx_gentools.def_enums import DB_MODE_READ, DB_MODE_WRITE, DB_MODE_CLEAR
from dnx_gentools.def_namedtuples import BLOCKED_DOM as _BLOCKED_DOM
from dnx_gentools.system_info import System as _System

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Optional

    from dnx_gentools.def_namedtuples import IPP_EVENT_LOG, DNS_EVENT_LOG, IPS_EVENT_LOG, GEOLOCATION_LOG, INF_EVENT_LOG

    from sqlite3 import Cursor


db = _db_conn.DBConnector

# ========================================
# INSERT ROUTINES
# ========================================
@db.register('dns_event', routine_type=DB_MODE_WRITE)
# standard input for dns proxy module database entries
def dns_event(cur: Cursor, log: DNS_EVENT_LOG) -> bool:
    cur.execute(
        'select count, last_seen from dnsproxy where src_ip=? and domain=? and action=?',
        (log.src_ip, log.request, log.action)
    )

    if existing_record := cur.fetchone():

        i, t = existing_record[0] + 1, existing_record[1]
        # idea:: make this configurable via the webui. a global setting would be easier, but per profile might be best.
        #  maybe we could use the dns id to detect retries and filter that way. this could be done in the dns module.
        # event log suppression. limit one every 10 seconds.
        if (int(log.timestamp) - t > 10):
            cur.execute(
                'update dnsproxy set count=?, last_seen=?, reason=? where src_ip=? and domain=? and action=?',
                (i, log.timestamp, log.reason, log.src_ip, log.request, log.action)
            )

    else:
        cur.execute(
            'insert into dnsproxy values (?, ?, ?, ?, ?, ?, ?)',
            (log.src_ip, log.request, log.category, log.reason, log.action, 1, log.timestamp)
        )

    return True

@db.register('dns_blocked', routine_type=DB_MODE_WRITE)
# used by dns proxy to authorize front end block page access.
def dns_blocked(cur: Cursor, log: DNS_EVENT_LOG) -> bool:
    cur.execute(
        'insert into blocked values (?, ?, ?, ?, ?)',
        (log.src_ip, log.request, log.category, log.reason, log.timestamp)
    )

    return True

@db.register('ips_event', routine_type=DB_MODE_WRITE)
# standard input for ips module database entries
def ips_event(cur: Cursor, log: IPS_EVENT_LOG) -> bool:
    cur.execute(
        'select last_seen from ips where src_ip=? and attack_type=? order by last_seen desc limit 1',
        (log.attacker, log.attack_type)
    )

    existing_record = cur.fetchone()
    if (existing_record):

        # idea:: make this configurable via the webui. a global setting would be easier, but per profile might be best.
        # event log suppression. limit one every 10 seconds.
        if (int(log.timestamp) - existing_record[0] < 10):
            return True

    cur.execute(
        'insert into ips values (?, ?, ?, ?, ?)',
        (log.attacker, log.protocol, log.attack_type, log.action, log.timestamp)
    )

    return True

@db.register('ipp_event', routine_type=DB_MODE_WRITE)
# standard input for ip proxy module database entries.
def ipp_event(cur: Cursor, log: IPP_EVENT_LOG) -> bool:
    cur.execute(
        'insert into ipproxy values (?, ?, ?, ?, ?, ?)',
        (log.local_ip, log.tracked_ip, log.category, log.direction, log.action, log.timestamp)
    )

    return True

@db.register('inf_event', routine_type=DB_MODE_WRITE)
def infected_event(cur: Cursor, log: INF_EVENT_LOG) -> bool:
    cur.execute(
        'select * from infectedclients where mac=? and detected_host=?',
        (log.client_mac, log.detected_host)
    )

    if existing_record := cur.fetchone():
        cur.execute(
            'update infectedclients set last_seen=? where mac=? and detected_host=?',
            (log.timestamp, log.client_mac, log.detected_host)
        )

    else:
        cur.execute(
            'insert into infectedclients values (?, ?, ?, ?, ?)',
            (log.client_mac, log.src_ip, log.detected_host, log.reason, log.timestamp)
        )

    return True

@db.register('geolocation', routine_type=DB_MODE_WRITE)
def geo_record(cur: Cursor, log: GEOLOCATION_LOG) -> bool:
    month = ','.join(_System.date()[:2])

    cur.execute('select * from geolocation where month=? and country=?', (month, log.cty_name))

    existing_record = cur.fetchone()
    # if it's the first time a country has been seen in the current month, it will be initialized with zeroes
    if (not existing_record):
        cur.execute('insert into geolocation values (?, ?, ?, ?, ?)', (month, log.cty_name, log.dir_name, 0, 0))

    # incremented count of the specific action specified in the log. (eg. blocked, allowed)
    cur.execute(
        f'update geolocation set {log.act_name}={log.act_name}+1 where month=? and country=? and direction=?',
        (month, log.cty_name, log.dir_name)
    )

    return True

@db.register('send_message', routine_type=DB_MODE_WRITE)
def send_message(cur: Cursor, *, msg_id: str, message) -> bool:
    cur.execute('insert into messenger values (?, ?, ?, ?, ?, ?, ?)', (msg_id, *message))

    return True

# ===============================
# REMOVE / CLEAR ROUTINES
# ===============================
@db.register('clear_infected', routine_type=DB_MODE_CLEAR)
# TODO: see why this wasnt being committed. i feel like it was an oversight.
# TODO: also type this
def clear_infected(cur: Cursor, infected_client, detected_host):
    cur.execute('delete from infectedclients where mac=? and detected_host=?', (infected_client, detected_host))

    return True

# ================================
# QUERY ROUTINES
# ================================
@db.register('blocked_domain', routine_type=DB_MODE_READ)
# query to authorize viewing of web block page and show block info for reference
def blocked_domain(cur: Cursor, *, domain: str, src_ip: str) -> _BLOCKED_DOM:
    for _ in range(6):
        cur.execute('select * from blocked where domain=? and src_ip=?', (domain, src_ip))
        try:
            return _BLOCKED_DOM(*cur.fetchone()[1:4])
        except TypeError:
            _fsleep(.25)

# todo: look into whether the optional src_ip is needed.
@db.register('last', routine_type=DB_MODE_READ)
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

@db.register('top', routine_type=DB_MODE_READ)
def top(cur: Cursor, count: int, *, table: str, action: str) -> list:
    if (action in ['all']):
        cur.execute(f'select * from {table} order by count desc limit {count}')

    elif (action in ['allowed', 'blocked']):
        cur.execute(f'select * from {table} where action=? order by count desc limit {count}', (action,))

    return cur.fetchall()

@db.register('top_dashboard', routine_type=DB_MODE_READ)
def top_dashboard(cur: Cursor, count, *, action):
    if (action in ['all']):
        cur.execute(f'select domain, category, sum(count) from dnsproxy group by domain order by count desc limit {count}')

    elif (action in ['allowed', 'blocked']):
        cur.execute(
            'select domain, category, sum(count) from dnsproxy where action=? '
            f'group by domain order by count desc limit {count}',
            (action,)
        )

    return [(x[0], x[1]) for x in cur.fetchall()]

@db.register('top_geolocation', routine_type=DB_MODE_READ)
def top_geolocation(cur: Cursor, count: int, *, action: str, direction: str) -> list[str]:
    month = ','.join(_System.date()[:2])

    # table has a separate column for allowed and blocked. this is why we select and sort on the action directly.
    # filtering out entries with no hits in the specified action.
    cur.execute(
        f'select country from geolocation where month=? and direction=? and {action} > 0 '
        f'order by {action} desc limit {count}', (month, direction)
    )

    return [x[0].replace('_', ' ') for x in cur.fetchall()]

@db.register('unique_domain_count', routine_type=DB_MODE_READ)
# TODO: see if this should use sum() instead of len() on the results
def unique_domain_count(cur: Cursor, *, action: str) -> int:
    if (action in ['all']):
        cur.execute('select domain, count(*) from dnsproxy group by domain')

    elif (action in ['allowed', 'blocked']):
        cur.execute('select domain, count(*) from dnsproxy where action=? group by domain', (action,))

    return len(cur.fetchall())

@db.register('total_request_count', routine_type=DB_MODE_READ)
# TODO: see if this should use sum() instead of iter add
def total_request_count(cur: Cursor, *, table: str, action: str) -> int:
    # todo: put a dnx_assert here.
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

@db.register('malware_count', routine_type=DB_MODE_READ)
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

@db.register('get_messages', routine_type=DB_MODE_READ)
def get_messages(cur: Cursor, *, sender: str, recipients: str) -> list:
    cur.execute(
        'select * from messenger where sender=? and recipients=? order by sent_at', (sender, recipients)
    )

    return cur.fetchall()
