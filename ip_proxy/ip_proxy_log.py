#!/usr/bin/env python3

from dnx_configure.dnx_constants import LOG, DIR, CONN
from dnx_configure.dnx_namedtuples import IPP_LOG, INFECTED_LOG
from dnx_logging.log_main import LogHandler


class Log(LogHandler):
    _infected_cats = ['command/control']

    @classmethod
    def log(cls, pkt, inspection):
        lvl, log = cls._generate_log(pkt, inspection)

        if (log):
            cls.event_log(pkt.timestamp, log, method='ipp')
            if (cls.syslog_enabled):
                cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(log))

    @staticmethod
    def generate_syslog_message(log):
        return ''.join([
            f'local.ip={log.local_ip}; tracked.ip={log.tracked_ip}; category={log.category}; ',
            f'direction={log.direction}; action={log.action}'
        ])

    @classmethod
    def _generate_log(cls, pkt, inspection):
        if (inspection.category in cls._infected_cats and pkt.direction is DIR.OUTBOUND and cls.current_lvl >= LOG.ALERT):
            log = IPP_LOG(
                pkt.conn.local_ip, pkt.conn.tracked_ip, inspection.category, pkt.direction.name, 'blocked'
            )

            log2 = INFECTED_LOG(
                pkt.src_mac.hex(), pkt.conn.local_ip, pkt.conn.tracked_ip, 'malware'
            )

            return LOG.ALERT, {'ipp': log, 'infected': log2}

        elif (cls.current_lvl >= LOG.NOTICE):
            action = 'blocked' if inspection.action is CONN.DROP else 'logged'
            # if (inspection.action is CONN.DROP):
            #     action = 'blocked'

            # elif (inspection.action is CONN.ACCEPT):
            #     action = 'logged'

            log = IPP_LOG(
                pkt.conn.local_ip, pkt.conn.tracked_ip, inspection.category, pkt.direction.name, action
            )

            return LOG.NOTICE, {'ipp': log}

        return LOG.NONE, {}
