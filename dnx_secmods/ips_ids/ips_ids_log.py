#!/usr/bin/env python3

from dnx_sysmods.configure.def_constants import *  # pylint: disable=unused-wildcard-import
from dnx_sysmods.configure.def_namedtuples import IPS_LOG
from dnx_sysmods.logging.log_main import LogHandler


class Log(LogHandler):

    @classmethod
    # TODO: if we relocate standard log method into parent LogHandler, this would need to stay/override since
    # it does not conform to proxy structure.
    def log(cls, pkt, scan_info=None, *, engine):
        if (engine is IPS.DDOS):
            lvl, log = cls._generate_ddos_log(pkt, scan_info)

        elif (engine is IPS.PORTSCAN):
            lvl, log = cls._generate_ps_log(pkt, scan_info)

        if (log):
            cls.event_log(pkt.timestamp, log, method='ips')
            if (cls.syslog_enabled):
                cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(log))

    @classmethod
    def _generate_ddos_log(cls, pkt, scan_info):
        if (cls.current_lvl >= LOG.ALERT and scan_info is IPS.LOGGED):
            log = IPS_LOG(pkt.tracked_ip, pkt.protocol.name, IPS.DDOS.name, 'logged') # pylint: disable=no-member

            cls.debug(f'[ddos][logged] {pkt.tracked_ip}')

            return LOG.ALERT, log

        if (cls.current_lvl >= LOG.CRITICAL and scan_info is IPS.FILTERED):
            log = IPS_LOG(pkt.tracked_ip, pkt.protocol.name, IPS.DDOS.name, 'filtered') # pylint: disable=no-member

            cls.debug(f'[ddos][filtered] {pkt.tracked_ip}')

            return LOG.CRITICAL, log

        return LOG.NONE, None

    @classmethod
    def _generate_ps_log(cls, pkt, scan_info):
        # will match if open ports are contained in pre detection logging (port was hit before flagged)
        if (scan_info.initial_block and scan_info.block_status in [IPS.LOGGED, IPS.MISSED]
                and cls.current_lvl >= LOG.ERROR):

            log = IPS_LOG(
                pkt.tracked_ip, pkt.protocol.name, IPS.PORTSCAN.name, scan_info.block_status.name # pylint: disable=no-member
            )

            cls.debug(f'[pscan/scan detected][{scan_info.block_status.name}] {pkt.tracked_ip}')

            return LOG.ERROR, log

        # will match if open ports are not contained in pre detection logging (port was hit before flagged)
        elif (scan_info.initial_block and scan_info.block_status is IPS.BLOCKED and cls.current_lvl >= LOG.WARNING):
            log = IPS_LOG(
                pkt.tracked_ip, pkt.protocol.name, IPS.PORTSCAN.name, 'blocked' # pylint: disable=no-member
            )

            cls.debug(f'[pscan/scan detected][blocked] {pkt.tracked_ip}')

            return LOG.WARNING, log

        return LOG.NONE, None

    # for sending message to the syslog service
    @staticmethod
    def generate_syslog_message(log):
        return f'src.ip={log.ip}; protocol={log.protocol}; attack_type={log.attack_type}; action={log.action}'
