#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import str_join
from dnx_gentools.def_enums import LOG, DIR, CONN
from dnx_gentools.def_namedtuples import IPP_EVENT_LOG, GEOLOCATION_LOG, INF_EVENT_LOG

from dnx_iptools.cprotocol_tools import itoip
from dnx_iptools.interface_ops import get_arp_table

from dnx_routines.logging.log_client import LogHandler

# DIRECT ACCESS FUNCTIONS
from dnx_routines.logging.log_client import (
    emergency, alert, critical, error, warning, notice, informational, debug, cli
)

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_namedtuples import IPP_INSPECTION_RESULTS
    from dnx_secmods.ip_proxy import IPPPacket


class Log(LogHandler):
    _infected_cats: ClassVar[list[str]] = ['command/control']

    @classmethod
    def log(cls, pkt: IPPPacket, inspection: IPP_INSPECTION_RESULTS, *, geo_only: bool = False):
        # inspection will be a tuple containing only geo name (geo_name,)
        if (geo_only):
            log = GEOLOCATION_LOG(inspection.category, pkt.direction.name, 'allowed')

            cls.event_log(pkt.timestamp, log, method='geolocation')

        # standard logging procedure.
        else:
            lvl, logs = cls._generate_log(pkt, inspection)
            for method, log in logs.items():
                cls.event_log(pkt.timestamp, log, method=method)

        # if (cls.syslog_enabled and log):
        #     cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(log))

    @staticmethod
    def generate_syslog_message(log):
        return str_join([
            f'local.ip={log.local_ip}; tracked.ip={log.tracked_ip}; category={str_join(log.category)}; ',
            f'direction={log.direction}; action={log.action}'
        ])

    @classmethod
    def _generate_log(cls, pkt: IPPPacket, inspection: IPP_INSPECTION_RESULTS) -> tuple[LOG, dict]:
        if (inspection.action is CONN.DROP):
            if (inspection.category in cls._infected_cats and pkt.direction is DIR.OUTBOUND and cls.current_lvl >= LOG.ALERT):
                log = IPP_EVENT_LOG(
                    pkt.local_ip, pkt.tracked_ip, inspection.category, pkt.direction.name, 'blocked'
                )

                log2 = INF_EVENT_LOG(
                    get_arp_table(host=itoip(pkt.local_ip)), pkt.local_ip, itoip(pkt.tracked_ip), 'malware'
                )

                log3 = GEOLOCATION_LOG(inspection.category[0], pkt.direction.name, 'blocked')

                return LOG.ALERT, {'ipp_event': log, 'inf_event': log2, 'geolocation': log3}

            elif (cls.current_lvl >= LOG.WARNING):
                log = IPP_EVENT_LOG(
                    pkt.local_ip, pkt.tracked_ip, inspection.category, pkt.direction.name, 'blocked'
                )

                log2 = GEOLOCATION_LOG(inspection.category[0], pkt.direction.name, 'blocked')

                return LOG.WARNING, {'ipp_event': log, 'geolocation': log2}

        # informational logging for all accepted connections
        elif (cls.current_lvl >= LOG.INFO):
            log = IPP_EVENT_LOG(
                pkt.local_ip, pkt.tracked_ip, inspection.category, pkt.direction.name, 'allowed'
            )

            log2 = GEOLOCATION_LOG(inspection.category[0], pkt.direction.name, 'allowed')

            return LOG.INFO, {'ipp_event': log, 'geolocation': log2}

        # this contains all that is needed to get the country information input into the database.
        return LOG.NONE, {'geolocation': GEOLOCATION_LOG(inspection.category[0], pkt.direction.name, 'allowed')}
