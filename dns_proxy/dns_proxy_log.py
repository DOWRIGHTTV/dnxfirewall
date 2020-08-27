#!/usr/bin/env python3

from dnx_logging.log_main import LogHandler
from dnx_configure.dnx_constants import LOG, DNS_CAT
from dnx_configure.dnx_namedtuples import DNS_LOG, INFECTED_LOG


class Log(LogHandler):

    @classmethod
    def log(cls, pkt, req):
        lvl, logs = cls._generate_event_log(pkt, req)
        for method, log in logs.items():
            cls.event_log(pkt.timestamp, log, method=method)

        if (cls.syslog_enabled and logs):
            cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(logs['dns']))

    @classmethod
    def _generate_event_log(cls, pkt, req):
        #supressing logs for dns over https. these are blocked in the backgrounds and should not notify the user.
        if (req.category in [DNS_CAT.doh]): pass

        ## Log to Infected Clients DB Table if matching malicious type categories
        elif (req.category in [DNS_CAT.malicious, DNS_CAT.cryptominer] and cls.current_lvl >= LOG.ALERT):
            log = DNS_LOG(f'{pkt.src_ip}', pkt.request, req.category, req.category, 'blocked')

            log2 = INFECTED_LOG(pkt.src_mac.hex(), f'{pkt.src_ip}', pkt.request, req.category)

            return LOG.ALERT, {'dns': log, 'blocked': log, 'infected': log2}

        # logs redirected/blocked requests
        elif (req.redirect and cls.current_lvl >= LOG.NOTICE):
            log = DNS_LOG(f'{pkt.src_ip}', pkt.request, req.category, req.reason, 'blocked')

            return LOG.NOTICE, {'dns': log, 'blocked': log}

        # logs all requests, regardless of action of proxy if not already logged
        elif (not req.redirect and cls.current_lvl >= LOG.INFO):
            log = DNS_LOG(f'{pkt.src_ip}', pkt.request, 'N/A', 'logging', 'allowed')

            return LOG.INFO, {'dns': log}

        return LOG.NONE, {}

    @staticmethod
    # for sending message to the syslog service
    def generate_syslog_message(log):
        message  = [
            f'src.ip={log.src_ip}; request={log.request}; category={log.category}; ',
            f'filter={log.reason}; action={log.action}'
        ]

        return ''.join(message)
