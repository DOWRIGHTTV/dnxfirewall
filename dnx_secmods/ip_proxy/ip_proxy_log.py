#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import str_join
from dnx_gentools.def_enums import LOG
from dnx_gentools.def_enums import DECISION, CONN_REJECT, CONN_INSPECT, CONN_DROP, CONN_ACCEPT
from dnx_gentools.def_enums import DIRECTION, DIR_OUTBOUND, DIR_INBOUND
from dnx_gentools.def_namedtuples import IPP_EVENT_LOG, GEOLOCATION_LOG, INF_EVENT_LOG

from dnx_iptools.cprotocol_tools import itoip
from dnx_iptools.interface_ops import get_arp_table

from dnx_routines.logging.log_client import LogHandler

# DIRECT ACCESS FUNCTIONS
# from dnx_routines.logging.log_client import (
#     emergency, alert, critical, error, warning, notice, informational, debug, cli
# )

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_namedtuples import IPP_INSPECTION_RESULTS
    from dnx_secmods.ip_proxy import IPPPacket

    LOG_ENTRIES: TypeAlias = list[tuple[EVENT_LOGS, LOG, str]]


MALWARE_CATEGORIES = ['command/control']

class Log(LogHandler):

    @classmethod
    def log(cls, pkt: IPPPacket, inspection: IPP_INSPECTION_RESULTS) -> None:

        for log, lvl, method in _generate_log(pkt, inspection):
            cls.event_log(pkt.timestamp, log, method=method)

        # if (cls.syslog_enabled and log):
        #     cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(log))

    @staticmethod
    def generate_syslog_message(log):
        return str_join([
            f'local.ip={log.local_ip}; tracked.ip={log.tracked_ip}; category={str_join(log.category)}; ',
            f'direction={log.direction}; action={log.action}'
        ])

def _generate_log(pkt: IPPPacket, inspection: IPP_INSPECTION_RESULTS) -> LOG_ENTRIES:

    log_entries = []

    if (inspection.action in [CONN_REJECT, CONN_DROP]):

        if (inspection.category in MALWARE_CATEGORIES and pkt.direction == DIR_OUTBOUND and Log.current_lvl >= LOG.ALERT):
            log_entries.append((
                INF_EVENT_LOG(get_arp_table(host=itoip(pkt.local_ip)), pkt.local_ip, itoip(pkt.tracked_ip), 'malware'),
                LOG.ALERT,
                'inf_event'
            ))

        if (Log.current_lvl >= LOG.WARNING):
            log_entries.append((
                IPP_EVENT_LOG(pkt.local_ip, pkt.tracked_ip, inspection.category, pkt.direction.name, 'blocked'),
                LOG.WARNING,
                'ipp_event'
            ))

    elif (inspection.action == CONN_ACCEPT):

        if (inspection.category in MALWARE_CATEGORIES and pkt.direction == DIR_OUTBOUND and Log.current_lvl >= LOG.EMERGENCY):
            log_entries.append((
                INF_EVENT_LOG(get_arp_table(host=itoip(pkt.local_ip)), pkt.local_ip, itoip(pkt.tracked_ip), 'malware'),
                LOG.EMERGENCY,
                'inf_event'
            ))

        # informational logging for all accepted connections
        if (Log.current_lvl >= LOG.INFO):
            log_entries.append((
                IPP_EVENT_LOG(pkt.local_ip, pkt.tracked_ip, inspection.category, pkt.direction.name, 'allowed'),
                LOG.INFO,
                'ipp_event'
            ))

    return log_entries
