#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_constants import TYPE_CHECKING, str_join
from dnx_gentools.def_enums import LOG, DNS_CAT, DNS_MALWARE_CATEGORIES as MALWARE_CATEGORIES
from dnx_gentools.def_namedtuples import DNS_EVENT_LOG, INF_EVENT_LOG

from dnx_iptools.interface_ops import get_arp_table

from dnx_routines.logging.log_client import LogHandler

if (TYPE_CHECKING):
    from dnx_gentools.def_typing import LOG_ENTRIES

    from dnx_gentools.def_namedtuples import DNS_INSPECTION_RESULTS
    from dnx_secmods.dns_proxy import DNSPacket

# MALWARE_CATEGORIES = [DNS_CAT.malicious, DNS_CAT.crypto_miner]


class Log(LogHandler):

    @classmethod
    def log(cls, pkt: DNSPacket, req: DNS_INSPECTION_RESULTS):

        for event, lvl, method in _generate_log(pkt, req):
            cls.event_log(event, method=method)

        # if (cls.syslog_enabled and logs):
        #     cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(logs['dns_request']))

    @staticmethod
    # for sending message to the syslog service # TODO: im sure more than just standard log need to be accepted
    def generate_syslog_message(log: DNS_EVENT_LOG) -> str:
        message = [
            f'src.ip={log.src_ip}; request={log.request}; category={log.category}; ',
            f'filter={log.reason}; action={log.action}'
        ]

        return str_join(message)


def _generate_log(pkt: DNSPacket, req: DNS_INSPECTION_RESULTS) -> LOG_ENTRIES:

    log_entries: LOG_ENTRIES = []

    # suppressing log for dns over https. these are blocked in the background and should not notify the user.
    # idea:: dns over https logs could be important due to its use in malware as an effective dns proxy bypass.
    if (req.category[1] in [DNS_CAT.dns_https]): pass

    client_ip = pkt.request_identifier[0]

    # request was blocked and redirected block page.
    if (req.redirect):

        # dns_blocked reason is just an identifier that this specific log object is used for blocked db table.
        log_entries.append((
            DNS_EVENT_LOG(pkt.timestamp, client_ip, pkt.qname, req.category, req.reason, 'dns_blocked'),
            LOG.ALERT,
            b'dns_blocked'
        ))

        # log to infected client db table if matching malicious type categories regardless of the action taken
        if (Log.current_lvl >= LOG.CRITICAL and req.category[1] in MALWARE_CATEGORIES):
            log_entries.append((
                INF_EVENT_LOG(pkt.timestamp, get_arp_table(host=client_ip), client_ip, pkt.qname, req.category),
                LOG.CRITICAL,
                b'inf_event'
            ))

        # log redirected/blocked requests
        if (Log.current_lvl >= LOG.WARNING):
            log_entries.append((
                DNS_EVENT_LOG(pkt.timestamp, pkt.request_identifier[0], pkt.qname, req.category, req.reason, 'blocked'),
                LOG.WARNING,
                b'dns_request'
            ))

    elif (not req.redirect):

        if (Log.current_lvl >= LOG.ALERT and req.category[1] in MALWARE_CATEGORIES):
            log_entries.append((
                INF_EVENT_LOG(pkt.timestamp, get_arp_table(host=client_ip), client_ip, pkt.qname, req.category),
                LOG.ALERT,
                b'inf_event'
            ))

        if (Log.current_lvl >= LOG.NOTICE):
            log_entries.append((
                DNS_EVENT_LOG(pkt.timestamp, pkt.request_identifier[0], pkt.qname, req.category, 'logging', 'allowed'),
                LOG.NOTICE,
                b'dns_request'
            ))

    return log_entries
