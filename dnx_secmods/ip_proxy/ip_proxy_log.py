#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_constants import TYPE_CHECKING, str_join
from dnx_gentools.def_enums import LOG, IP_MALWARE_CATEGORIES as MALWARE_CATEGORIES
from dnx_gentools.def_enums import CONN_REJECT, CONN_DROP, CONN_ACCEPT
from dnx_gentools.def_enums import DIR_OUTBOUND
from dnx_gentools.def_namedtuples import IPP_EVENT_LOG, INF_EVENT_LOG

from dnx_iptools.cprotocol_tools import itoip
from dnx_iptools.interface_ops import get_arp_table

from dnx_routines.logging.log_client import LogHandler

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_typing import LOG_ENTRIES

    from dnx_gentools.def_namedtuples import IPP_INSPECTION_RESULTS
    from dnx_secmods.ip_proxy import IPPPacket


# MALWARE_CATEGORIES = ['command/control']

class Log(LogHandler):

    @classmethod
    def log(cls, pkt: IPPPacket, inspection: IPP_INSPECTION_RESULTS) -> None:

        for log, lvl, method in _generate_log(pkt, inspection):
            cls.event_log(log, method)

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

    malware_criteria = pkt.direction == DIR_OUTBOUND and inspection.category[1] in MALWARE_CATEGORIES

    if (inspection.action in [CONN_REJECT, CONN_DROP]):

        if (Log.current_lvl >= LOG.ALERT and malware_criteria):
            log_entries.append((
                INF_EVENT_LOG(pkt.timestamp, get_arp_table(host=itoip(pkt.local_ip)), pkt.local_ip, itoip(pkt.tracked_ip), inspection.category),
                LOG.ALERT,
                b'inf_event'
            ))

        if (Log.current_lvl >= LOG.WARNING):
            log_entries.append((
                IPP_EVENT_LOG(pkt.timestamp, pkt.local_ip, pkt.tracked_ip, inspection.category, pkt.direction.name, 'blocked'),
                LOG.WARNING,
                b'ipp_event'
            ))

    elif (inspection.action == CONN_ACCEPT):

        if (Log.current_lvl >= LOG.EMERGENCY and malware_criteria):
            log_entries.append((
                INF_EVENT_LOG(pkt.timestamp, get_arp_table(host=itoip(pkt.local_ip)), pkt.local_ip, itoip(pkt.tracked_ip), inspection.category),
                LOG.EMERGENCY,
                b'inf_event'
            ))

        # informational logging for all accepted connections
        if (Log.current_lvl >= LOG.INFO):
            log_entries.append((
                IPP_EVENT_LOG(pkt.timestamp, pkt.local_ip, pkt.tracked_ip, inspection.category, pkt.direction.name, 'allowed'),
                LOG.INFO,
                b'ipp_event'
            ))

    return log_entries
