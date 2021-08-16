#!/usr/bin/env python3

from dnx_configure.dnx_constants import LOG, DNS_CAT, str_join
from dnx_configure.dnx_namedtuples import DNS_LOG, INFECTED_LOG
from dnx_iptools.dnx_interface import get_arp_table

from dnx_logging.log_main import LogHandler


class Log(LogHandler):

    @classmethod
    # TODO: this looks standard and can probably just be relocated into the parent LogHandler.
    def log(cls, pkt, req):
        lvl, logs = cls._generate_event_log(pkt, req)
        for method, log in logs.items():
            cls.event_log(pkt.timestamp, log, method=method)

        if (cls.syslog_enabled and logs):
            cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(logs['dns']))

    @classmethod
    def _generate_event_log(cls, pkt, req):
        # supressing logs for dns over https. these are blocked in the backgrounds and should not notify the user.
        if (req.category in [DNS_CAT.doh]): pass

        # log to infected clients db table if matching malicious type categories
        elif (req.category in [DNS_CAT.malicious, DNS_CAT.cryptominer] and cls.current_lvl >= LOG.ALERT):
            log = DNS_LOG(f'{pkt.src_ip}', pkt.request, req.category.name, req.reason, 'blocked')

            log2 = INFECTED_LOG(get_arp_table(host=pkt.src_ip), f'{pkt.src_ip}', pkt.request, req.category.name)

            return LOG.ALERT, {'dns': log, 'blocked': log, 'infected': log2}

        # logs redirected/blocked requests
        elif (req.redirect and cls.current_lvl >= LOG.WARNING):
            log = DNS_LOG(f'{pkt.src_ip}', pkt.request, req.category.name, req.reason, 'blocked')

            return LOG.WARNING, {'dns': log, 'blocked': log}

        # NOTE: recent change to have allowed requests log enabled at NOTICE or above
        elif (not req.redirect and cls.current_lvl >= LOG.NOTICE):
            log = DNS_LOG(f'{pkt.src_ip}', pkt.request, req.category.name, 'logging', 'allowed')

            return LOG.NOTICE, {'dns': log}

        return LOG.NONE, {}

    @staticmethod
    # for sending message to the syslog service
    def generate_syslog_message(log):
        message  = [
            f'src.ip={log.src_ip}; request={log.request}; category={log.category}; ',
            f'filter={log.reason}; action={log.action}'
        ]

        return str_join(message)
