#!/usr/bin/env python3

from dnx_configure.dnx_constants import LOG, DIR, CONN
from dnx_configure.dnx_namedtuples import IPP_LOG, INFECTED_LOG
from dnx_logging.log_main import LogHandler


class Log(LogHandler):
    _infected_cats = ['command/control']

    @classmethod
    # TODO: this looks standard and can probably just be relocated into the parent LogHandler.
    def log(cls, pkt, inspection):
        lvl, logs = cls._generate_log(pkt, inspection)
        for method, log in logs.items():
            cls.event_log(pkt.timestamp, log, method=method)

        if (cls.syslog_enabled and logs):
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
                pkt.conn.local_ip, pkt.conn.tracked_ip, inspection.category.name, pkt.direction.name, 'blocked'
            )

            log2 = INFECTED_LOG(
                pkt.src_mac.hex(), pkt.conn.local_ip, pkt.conn.tracked_ip, 'malware'
            )

            return LOG.ALERT, {'ipp': log, 'infected': log2}

        elif (cls.current_lvl >= LOG.NOTICE):
            action = 'blocked' if inspection.action is CONN.DROP else 'logged'

            log = IPP_LOG(
                pkt.conn.local_ip, pkt.conn.tracked_ip, inspection.category.name, pkt.direction.name, action
            )

            return LOG.NOTICE, {'ipp': log}

        return LOG.NONE, {}
