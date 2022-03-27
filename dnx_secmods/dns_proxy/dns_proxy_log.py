#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import str_join
from dnx_gentools.def_enums import LOG, DNS_CAT
from dnx_gentools.def_namedtuples import DNS_REQUEST_LOG, INFECTED_LOG

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
    from dnx_gentools.def_namedtuples import DNS_REQUEST_RESULTS


class Log(LogHandler):

    @classmethod
    # TODO: this looks standard and can probably just be relocated into the parent LogHandler.
    def log(cls, pkt: DNSPacket, req: DNS_REQUEST_RESULTS):

        lvl, logs = cls._generate_event_log(pkt, req)
        for method, log in logs.items():
            cls.event_log(pkt.timestamp, log, method=method)

        if (cls.syslog_enabled and logs):
            cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(logs['dns_request']))

    @classmethod
    def _generate_event_log(cls, pkt: DNSPacket, req: DNS_REQUEST_RESULTS) -> tuple[LOG, dict]:
        # suppressing logs for dns over https. these are blocked in the background and should not notify the user.
        if (req.category in [DNS_CAT.doh]): pass

        # log to infected client db table if matching malicious type categories
        elif (req.category in [DNS_CAT.malicious, DNS_CAT.cryptominer] and cls.current_lvl >= LOG.ALERT):
            client_ip = pkt.request_identifier[0]

            log = DNS_REQUEST_LOG(client_ip, pkt.qname, req.category.name, req.reason, 'dns_blocked')

            log2 = INFECTED_LOG(get_arp_table(host=client_ip), client_ip, pkt.qname, req.category.name)

            return LOG.ALERT, {'dns_request': log, 'dns_blocked': log, 'inf_event': log2}

        # logs redirected/blocked requests
        elif (req.redirect and cls.current_lvl >= LOG.WARNING):
            log = DNS_REQUEST_LOG(pkt.request_identifier[0], pkt.qname, req.category.name, req.reason, 'blocked')

            return LOG.WARNING, {'dns_request': log, 'dns_blocked': log}

        # NOTE: recent change to have allowed requests log enabled at NOTICE or above
        elif (not req.redirect and cls.current_lvl >= LOG.NOTICE):
            log = DNS_REQUEST_LOG(pkt.request_identifier[0], pkt.qname, req.category.name, 'logging', 'allowed')

            return LOG.NOTICE, {'dns_request': log}

        return LOG.NONE, {}

    @staticmethod
    # for sending message to the syslog service # TODO: im sure more than just standard logs need to be accepted
    def generate_syslog_message(log: DNS_REQUEST_LOG) -> str:
        message = [
            f'src.ip={log.src_ip}; request={log.request}; category={log.category}; ',
            f'filter={log.reason}; action={log.action}'
        ]

        return str_join(message)
