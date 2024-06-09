#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_exceptions import dnx_assert
from dnx_gentools.def_constants import TYPE_CHECKING
from dnx_gentools.def_enums import LOG, IPS
from dnx_gentools.def_namedtuples import IPS_EVENT_LOG

from dnx_iptools.cprotocol_tools import itoip

from dnx_routines.logging.log_client import LogHandler

if (TYPE_CHECKING):
    from dnx_gentools.def_typing import Union, Optional
    from dnx_gentools.def_typing import LOG_ENTRY

    from dnx_gentools.def_namedtuples import IPS_SCAN_RESULTS
    from dnx_secmods.ids_ips import IPSPacket


class Log(LogHandler):

    @classmethod
    def log(cls, pkt: IPSPacket, inspection: Union[IPS, IPS_SCAN_RESULTS], *, engine: IPS) -> None:

        if (engine is IPS.DDOS):
            log_data = _generate_ddos_log(pkt, inspection)

        elif (engine is IPS.PORTSCAN):
            log_data = _generate_ps_log(pkt, inspection)

        else:
            dnx_assert(False, f'Invalid IPS engine: {engine}')

        if (log_data):
            log, lvl, method = log_data

            cls.event_log(log, method)

            # if (cls.syslog_enabled):
            #     cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(log))

    # for sending a message to the syslog servers
    @staticmethod
    def generate_syslog_message(log: IPS_EVENT_LOG) -> str:
        return f'src.ip={log.attacker}; protocol={log.protocol}; attack_type={log.attack_type}; action={log.action}'


def _generate_ddos_log(pkt: IPSPacket, scan: IPS) -> Optional[LOG_ENTRY]:

    if (Log.current_lvl >= LOG.ALERT and scan is IPS.LOGGED):

        Log.debug(f'[ddos][logged] {itoip(pkt.tracked_ip)}')

        return (
            IPS_EVENT_LOG(pkt.timestamp, pkt.tracked_ip, pkt.protocol, (IPS.DDOS.name, pkt.ids_profile), 'logged'),
            LOG.ALERT,
            b'ips_event'
        )

    elif (Log.current_lvl >= LOG.CRITICAL and scan is IPS.FILTERED):

        Log.debug(f'[ddos][filtered] {itoip(pkt.tracked_ip)}')

        return (
            IPS_EVENT_LOG(pkt.timestamp, pkt.tracked_ip, pkt.protocol, (IPS.DDOS.name, pkt.ids_profile), 'filtered'),
            LOG.CRITICAL,
            b'ips_event'
        )

    return None

def _generate_ps_log(pkt: IPSPacket, scan: IPS_SCAN_RESULTS) -> Optional[LOG_ENTRY]:

    # ERROR/3 - MISSED or IDS MODE
    if (scan.initial_block and scan.block_status in [IPS.LOGGED, IPS.MISSED] and Log.current_lvl >= LOG.ERROR):

        Log.debug(f'[pscan/scan detected][{scan.block_status.name}] {itoip(pkt.tracked_ip)}')

        return (
            IPS_EVENT_LOG(pkt.timestamp, pkt.tracked_ip, pkt.protocol, (IPS.PORTSCAN.name, pkt.ids_profile), scan.block_status.name),
            LOG.ERROR,
            b'ips_event'
        )

    # WARNING/4 - BLOCKED or REJECTED
    elif (scan.initial_block and scan.block_status in [IPS.BLOCKED, IPS.REJECTED] and Log.current_lvl >= LOG.WARNING):

        Log.debug(f'[pscan/scan detected][{scan.block_status.name}] {itoip(pkt.tracked_ip)}')

        return (
            IPS_EVENT_LOG(pkt.timestamp, pkt.tracked_ip, pkt.protocol, (IPS.PORTSCAN.name, pkt.ids_profile), scan.block_status.name),
            LOG.WARNING,
            b'ips_event'
        )

    return None
