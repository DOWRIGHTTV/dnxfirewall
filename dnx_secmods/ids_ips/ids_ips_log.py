#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import LOG, IPS
from dnx_gentools.def_namedtuples import IPS_EVENT_LOG

from dnx_iptools.cprotocol_tools import itoip

from dnx_routines.logging.log_client import LogHandler

# DIRECT ACCESS FUNCTIONS
# from dnx_routines.logging.log_client import (
#     emergency, alert, critical, error, warning, notice, informational, debug, cli
# )

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_namedtuples import IPS_SCAN_RESULTS
    from dnx_secmods.ids_ips import IPSPacket


class Log(LogHandler):

    @classmethod
    def log(cls, pkt: IPSPacket, inspection: Union[IPS, IPS_SCAN_RESULTS], *, engine: IPS) -> None:
        if (engine is IPS.DDOS):
            lvl, log = _generate_ddos_log(pkt, inspection)

        elif (engine is IPS.PORTSCAN):
            lvl, log = _generate_ps_log(pkt, inspection)

        else: return

        if (log):
            cls.event_log(pkt.timestamp, log, method='ips_event')
            # if (cls.syslog_enabled):
            #     cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(log))

    # for sending a message to the syslog servers
    @staticmethod
    def generate_syslog_message(log: IPS_EVENT_LOG) -> str:
        return f'src.ip={log.attacker}; protocol={log.protocol}; attack_type={log.attack_type}; action={log.action}'


def _generate_ddos_log(pkt: IPSPacket, scan: IPS) -> tuple[LOG, Optional[IPS_EVENT_LOG]]:

    if (scan is IPS.LOGGED and Log.current_lvl >= LOG.ALERT):

        Log.debug(f'[ddos][logged] {itoip(pkt.tracked_ip)}')

        return LOG.ALERT, IPS_EVENT_LOG(pkt.tracked_ip, pkt.protocol.name, IPS.DDOS.name, 'logged')

    elif (scan is IPS.FILTERED and Log.current_lvl >= LOG.CRITICAL):

        Log.debug(f'[ddos][filtered] {itoip(pkt.tracked_ip)}')

        return LOG.CRITICAL, IPS_EVENT_LOG(pkt.tracked_ip, pkt.protocol.name, IPS.DDOS.name, 'filtered')

    return LOG.NONE, None

def _generate_ps_log(pkt: IPSPacket, scan: IPS_SCAN_RESULTS) -> tuple[LOG, Optional[IPS_EVENT_LOG]]:

    # ERROR/3 - MISSED or IDS MODE
    if (scan.initial_block and scan.block_status in [IPS.LOGGED, IPS.MISSED] and Log.current_lvl >= LOG.ERROR):

        Log.debug(f'[pscan/scan detected][{scan.block_status.name}] {itoip(pkt.tracked_ip)}')

        return LOG.ERROR, IPS_EVENT_LOG(pkt.tracked_ip, pkt.protocol.name, IPS.PORTSCAN.name, scan.block_status.name)

    # WARNING/4 - BLOCKED or REJECTED
    elif (scan.initial_block and scan.block_status in [IPS.BLOCKED, IPS.REJECTED] and Log.current_lvl >= LOG.WARNING):

        Log.debug(f'[pscan/scan detected][{scan.block_status.name}] {itoip(pkt.tracked_ip)}')

        return LOG.WARNING, IPS_EVENT_LOG(pkt.tracked_ip, pkt.protocol.name, IPS.PORTSCAN.name, scan.block_status.name)

    return LOG.NONE, None
