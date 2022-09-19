#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import LOG, IPS
from dnx_gentools.def_namedtuples import IPS_EVENT_LOG

from dnx_iptools.cprotocol_tools import itoip

from dnx_routines.logging.log_client import LogHandler

# DIRECT ACCESS FUNCTIONS
from dnx_routines.logging.log_client import (
    emergency, alert, critical, error, warning, notice, informational, debug, cli
)

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_namedtuples import IPS_SCAN_RESULTS
    from dnx_secmods.ips_ids import IPSPacket


class Log(LogHandler):

    @classmethod
    def log(cls, pkt: IPSPacket, scan_info: Union[IPS, IPS_SCAN_RESULTS], *, engine: IPS) -> None:
        if (engine is IPS.DDOS):
            lvl, log = cls._generate_ddos_log(pkt, scan_info)

        elif (engine is IPS.PORTSCAN):
            lvl, log = cls._generate_ps_log(pkt, scan_info)

        else: return

        if (log):
            cls.event_log(pkt.timestamp, log, method='ips_event')
            if (cls.syslog_enabled):
                cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(log))

    @classmethod
    def _generate_ddos_log(cls, pkt: IPSPacket, scan_info: IPS) -> tuple[LOG, Optional[IPS_EVENT_LOG]]:

        if (cls.current_lvl >= LOG.ALERT and scan_info is IPS.LOGGED):
            log = IPS_EVENT_LOG(pkt.tracked_ip, pkt.protocol.name, IPS.DDOS.name, 'logged')

            cls.debug(f'[ddos][logged] {itoip(pkt.tracked_ip)}')

            return LOG.ALERT, log

        if (cls.current_lvl >= LOG.CRITICAL and scan_info is IPS.FILTERED):
            log = IPS_EVENT_LOG(pkt.tracked_ip, pkt.protocol.name, IPS.DDOS.name, 'filtered')

            cls.debug(f'[ddos][filtered] {itoip(pkt.tracked_ip)}')

            return LOG.CRITICAL, log

        return LOG.NONE, None

    @classmethod
    def _generate_ps_log(cls, pkt: IPSPacket, scan_info: IPS_SCAN_RESULTS) -> tuple[LOG, Optional[IPS_EVENT_LOG]]:

        # ERROR/3 - MISSED or IDS MODE
        if (scan_info.initial_block and scan_info.block_status in [IPS.LOGGED, IPS.MISSED]
                and cls.current_lvl >= LOG.ERROR):

            log = IPS_EVENT_LOG(
                pkt.tracked_ip, pkt.protocol.name, IPS.PORTSCAN.name, scan_info.block_status.name
            )

            cls.debug(f'[pscan/scan detected][{scan_info.block_status.name}] {itoip(pkt.tracked_ip)}')

            return LOG.ERROR, log

        # WARNING/4 - BLOCKED or REJECTED
        elif (scan_info.initial_block and scan_info.block_status in [IPS.BLOCKED, IPS.REJECTED]
              and cls.current_lvl >= LOG.WARNING):

            log = IPS_EVENT_LOG(
                pkt.tracked_ip, pkt.protocol.name, IPS.PORTSCAN.name, scan_info.block_status.name
            )

            cls.debug(f'[pscan/scan detected][{scan_info.block_status.name}] {itoip(pkt.tracked_ip)}')

            return LOG.WARNING, log

        return LOG.NONE, None

    # for sending a message to the syslog servers
    @staticmethod
    def generate_syslog_message(log: IPS_EVENT_LOG) -> str:
        return f'src.ip={log.attacker}; protocol={log.protocol}; attack_type={log.attack_type}; action={log.action}'
