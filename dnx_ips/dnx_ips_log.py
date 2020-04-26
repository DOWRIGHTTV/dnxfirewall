#!/usr/bin/env python3

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_configure.dnx_namedtuples import IPS_LOG

from dnx_logging.log_main import LogHandler

class Log(LogHandler):

    @classmethod
    def log(cls, pkt, scan_info=None, *, engine):
        if (engine == IPS.DDOS):
            lvl, log = cls._generate_ddos_log(pkt)

        elif (engine == IPS.PORTSCAN):
            lvl, log = cls._generate_ps_log(pkt, scan_info)

        if (log):
            cls.event_log(pkt.timestamp, log, method='ips')
            if (cls.syslog_enabled):
                cls.slog_log(LOG.EVENT, lvl, cls.generate_syslog_message(log))

    @classmethod
    def _generate_ddos_log(cls, pkt):
        if (cls.current_lvl >= LOG.CRITICAL):
            log = IPS_LOG(pkt.conn.tracked_ip, pkt.protocol.name, IPS.DDOS.name, 'filtered')

            return LOG.CRITICAL, log

        return LOG.NONE, ''

    @classmethod
    def _generate_ps_log(cls,  pkt, scan_info):
        # will match if open ports are contained in pre detection logging (port was hit before flagged)
        if (scan_info.initial_block and scan_info.block_status is IPS.MISSED and cls.current_lvl >= LOG.WARNING):
            log = IPS_LOG(pkt.conn.tracked_ip, pkt.protocol.name, IPS.PORTSCAN.name, 'missed')

            cls.debug(f'ACTIVE BLOCK: {pkt.conn.tracked_ip}')

            return LOG.WARNING, log

        # will match if open ports are not contained in pre detection logging (port was hit before flagged)
        elif (scan_info.initial_block and scan_info.block_status is IPS.BLOCKED and cls.current_lvl >= LOG.NOTICE):
            log = IPS_LOG(pkt.conn.tracked_ip, pkt.protocol.name, IPS.PORTSCAN.name, 'blocked')

            cls.debug(f'ACTIVE BLOCK: {pkt.conn.tracked_ip}')

            return LOG.NOTICE, log

        # will match if the rules above do not and the connection is marked to be actively blocked. this doesnt care about whether
        # the scan had already been blocked and has an active firewall rule, because it assumes blocking disabled.
        elif (scan_info.block_status is IPS.LOGGED and cls.current_lvl >= LOG.INFO):
            log = IPS_LOG(pkt.conn.tracked_ip, pkt.protocol.name, IPS.PORTSCAN.name, 'logged')

            cls.debug(f'ACTIVE SCAN LOGGED: {pkt.conn.tracked_ip}')

            return LOG.INFO, log

    # for sending message to the syslog service
    @staticmethod
    def generate_syslog_message(log):
        message  = [
            f'src.ip={log.ip}; protocol={log.protocol}; attack_type={log.attack_type}; ',
            f'action={log.action}'
        ]

        return ''.join(message)
