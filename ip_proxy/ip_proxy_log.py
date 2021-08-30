#!/usr/bin/env python3

from dnx_configure.dnx_constants import LOG, DIR, CONN, str_join
from dnx_configure.dnx_namedtuples import IPP_LOG, GEO_LOG, INFECTED_LOG
from dnx_iptools.dnx_interface import get_arp_table

from dnx_logging.log_main import LogHandler


class Log(LogHandler):
    _infected_cats = ['command/control']

    @classmethod
    # TODO: this looks standard and can probably just be relocated into the parent LogHandler.
    def log(cls, pkt, inspection):
        lvl, logs = cls._generate_log(pkt, inspection)
        for method, log in logs.items():
            cls.event_log(pkt.timestamp, log, method=method)

        # if (cls.syslog_enabled and logs):
        #     cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(log))

    @staticmethod
    def generate_syslog_message(log):
        return str_join([
            f'local.ip={log.local_ip}; tracked.ip={log.tracked_ip}; category={str_join(log.category)}; ',
            f'direction={log.direction}; action={log.action}'
        ])

    @classmethod
    def _generate_log(cls, pkt, inspection):
        if (inspection.action is CONN.DROP):
            if (inspection.category in cls._infected_cats and pkt.direction is DIR.OUTBOUND and cls.current_lvl >= LOG.ALERT):
                log = IPP_LOG(
                    pkt.local_ip, pkt.tracked_ip, inspection.category, pkt.direction.name, 'blocked'
                )

                log2 = INFECTED_LOG(
                    get_arp_table(host=pkt.local_ip), pkt.local_ip, pkt.tracked_ip, 'malware'
                )

                log3 = GEO_LOG(inspection.category[0], pkt.direction.name, 'blocked')

                return LOG.ALERT, {'ipp': log, 'infected': log2, 'geo': log3}

            elif (cls.current_lvl >= LOG.WARNING):
                log = IPP_LOG(
                    pkt.local_ip, pkt.tracked_ip, inspection.category, pkt.direction.name, 'blocked'
                )

                log2 = GEO_LOG(inspection.category[0], pkt.direction.name, 'blocked')

                return LOG.WARNING, {'ipp': log, 'geo': log2}

        # informational logging for all accepted connections
        elif (cls.current_lvl >= LOG.INFO):
            log = IPP_LOG(pkt.local_ip, pkt.tracked_ip, inspection.category, pkt.direction.name, 'allowed')

            log2 = GEO_LOG(inspection.category[0], pkt.direction.name, 'allowed')

            return LOG.INFO, {'ipp': log, 'geo': log2}

        # this contains all that is needed to get the country information input into the database.
        return LOG.NONE, {'geo': GEO_LOG(inspection.category[0], pkt.direction.name, 'allowed')}
