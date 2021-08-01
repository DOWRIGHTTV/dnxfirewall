#!/usr/bin/env python3

import os, sys
import time
import threading
import traceback

from copy import copy

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_standard_tools import dynamic_looper
from dnx_configure.dnx_namedtuples import IPS_SCAN_RESULTS, DDOS_TRACKERS, PSCAN_TRACKERS
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_iptables import IPTablesManager

from dnx_iptools.dnx_parent_classes import NFQueue
from dnx_ips.dnx_ips_log import Log
from dnx_ips.dnx_ips_automate import Configuration
from dnx_ips.dnx_ips_packets import IPSPacket, IPSResponse

from dnx_configure.dnx_code_profiler import profiler

LOG_NAME = 'ips'


# TODO: CONVERT PROTOCOL TO ENUMS SINCE WE ARE RESTRICTING VIA IPTABLES/NFQUEUE TO ONLY PROTOCOLS WE CARE ABOUT!!!.
# TODO: ENSURE WE CLEAN TIMED OUT HOSTS FROM HOST TRACKING DICTS AT X (10?) MIN INTERVALS!!
class IPS_IDS(NFQueue):
    fw_rules = {}
    connection_limits = {}
    ip_whitelist = {}
    open_ports = {
        PROTO.TCP: {},
        PROTO.UDP:{}
    }

    ddos_prevention = False
    portscan_prevention = False
    portscan_reject = False
    ids_mode = False # TODO: implement this throughout
    broadcast = None

    ddos_engine_enabled = False
    ps_engine_enabled   = False

    _packet_parser = IPSPacket.netfilter # alternate constructor, but does not return self

    @classmethod
    def _setup(cls):
        Configuration.setup(cls)
        IPSResponse.setup(cls, Log)

        cls.set_proxy_callback(func=Inspect.portscan) # this will get called after parsing is complete.

        Log.notice(f'{cls.__name__} initialization complete.')

    # if nothing is enabled the packet will be sent back to iptables for further inspection
    def _pre_check(self, nfqueue):
        # if ip proxy marked for drop we will do that first
        if (nfqueue.get_mark() == IP_PROXY_DROP):
            nfqueue.drop()

            # if ddos engine is enabled we want to inspect regardless of ip proxy decision
            if (self.ddos_engine_enabled):
                self.inspection_required = IPS.DDOS

                return True

            return False

        # the following are to match the specific condition of the system to make it easier to deal with in the
        # pre inspection method.
        if (self.ps_engine_enabled and self.ddos_engine_enabled):
            self.inspection_required = IPS.BOTH

        elif (self.ps_engine_enabled):
            self.inspection_required = IPS.PORTSCAN

        # NOTE: we could forward the packet here, but as of right now i am feeling it to be in pre inspect after
        # its conditions were simplified. we can look into the potential performance gain of doing it here later
        # if it seems necessary.
        elif (self.ddos_engine_enabled):
            self.inspection_required = IPS.DDOS

        else:
            self.forward_packet(nfqueue)

            return False

        return True

    def _pre_inspect(self, packet):
        # whilelisted source ip does not need to be inspected
        # NOTE: this could be a duplicate decision if ddos engine is only thing enabled. THIS IS ONLY RELEVANT
        # IF PRE CHECK HAS THE FORWARD PACKET CALL. AS OF RIGHT NOW IT DOES NOT.
        if (packet.src_ip in self.ip_whitelist):
            self.forward_packet(packet.nfqueue)

            return False

        # ternary operations to define local var for broadcast packet
        broadcast = True if packet.dst_ip == self.broadcast else False

        if (not broadcast):
            if (self.inspection_required in [IPS.BOTH, IPS.DDOS]):
                threading.Thread(target=Inspect.ddos, args=(packet,)).start()

            # will mark for inspection by portscan if protocol is udp or tcp
            if (packet.protocol is not PROTO.ICMP and self.inspection_required in [IPS.BOTH, IPS.PORTSCAN]):
                return True

        self.forward_packet(packet.nfqueue)

        # default action | inspection not required
        return False

    @staticmethod
    def forward_packet(nfqueue):
        nfqueue.set_mark(WAN_ZONE_FIREWALL)
        nfqueue.repeat()

    @property
    def inspection_enabled(self):
        if (self.ps_engine_enabled or self.ddos_engine_enabled):
            return True

        return False


class Inspect:
    _IPS = IPS_IDS
    _IPSResponse = IPSResponse

    pscan_tracker = {
        proto: PSCAN_TRACKERS(threading.Lock(), {})
            for proto in [PROTO.TCP, PROTO.UDP]
    }
    ddos_tracker = {
        proto: DDOS_TRACKERS(threading.Lock(), {})
            for proto in [PROTO.TCP, PROTO.UDP, PROTO.ICMP]
    }

    @classmethod
    def portscan(cls, packet):
        self = cls()
        self._portscan_inspect(cls._IPS, packet)

    @classmethod
    # NOTE: not passing in _IPS object since it doesnt seem to be worth it. maybe can for consistency though.
    def ddos(cls, packet):
        self = cls()
        self._ddos_inspect(packet)

    # this method drives the overall logic of the ddos detection engine. it will try to conserve resources by not sending packets
    # that dont need to be checked or logged under normal conditions.
    def _ddos_inspect(self, packet):
        ddos = self.ddos_tracker[packet.protocol]
        with ddos.lock:
            if not self._ddos_detected(ddos.tracker, packet): return

        if (self._IPS.ids_mode):
            Log.log(packet, IPS.LOGGED, engine=IPS.DDOS)

        # TODO: see if changing the iptables table to RAW would be better. It should be able to do all the standard filtering and is
        # processed even before mangle. to test, just inject rule into RAW and see if functonality is the same.
        elif (self._IPS.ddos_prevention):
            IPTablesManager.proxy_add_rule(packet.conn.tracked_ip, table='mangle', chain='IPS')

            Log.log(packet, IPS.FILTERED, engine=IPS.DDOS)

    def _ddos_detected(self, ddos_tracker, packet):
        tracked_ip = ddos_tracker.get(packet.conn.tracked_ip, None)
        if (not tracked_ip or fast_time() - tracked_ip['last_seen'] > 15):
            self._add_to_tracker(ddos_tracker, packet, engine=IPS.DDOS)

        else:
            tracked_ip['count'] += 1
            tracked_ip['last_seen'] = packet.timestamp

            # if conn limit exceeded and host is not already marked, returns active ddos and add ip to tracker
            if self._threshhold_exceeded(tracked_ip, packet):
                Log.debug(f'ACTIVE BLOCK: {packet.conn.tracked_ip}')

                # this is to supress log entries for ddos hosts that are being detected by the engine since there is a delay
                # between detection and kernel offload or some packets are already in queue
                if (packet.conn.tracked_ip not in self._IPS.fw_rules):
                    self._IPS.fw_rules[packet.conn.tracked_ip] = packet.timestamp

                    return True

        return False

    def _threshhold_exceeded(self, tracked_ip, packet):
        elapsed_time = packet.timestamp - tracked_ip['initial']
        if (elapsed_time < 2): return False

        protocol_src_limit = self._IPS.connection_limits[packet.protocol]
        if (tracked_ip['count']/elapsed_time < protocol_src_limit): return False

        # host is now marked as engaging in active d/dos attack.
        Log.debug('CPS: {}'.format(tracked_ip['count']/elapsed_time))

        return True

    # this method drives the overall logic of the portscan detection engine. it will try to conserve resources but not sending packets
    # that dont need to be checked or logged under normal conditions.
    def _portscan_inspect(self, IPS_IDS, packet):
        pscan = self.pscan_tracker[packet.protocol]
        with pscan.lock:
            initial_block, active_scanner, pre_detection_logging = self._portscan_detect(pscan.tracker, packet)

        if (not active_scanner):
            Log.debug(f'[accept] {packet.src_ip}:{packet.src_port} > {packet.dst_ip}:{packet.dst_port}.')
            IPS_IDS.forward_packet(packet.nfqueue)

            return

        if (IPS_IDS.ids_mode):
            IPS_IDS.forward_packet(packet.nfqueue)
            block_status = IPS.LOGGED

        elif (IPS_IDS.portscan_prevention):
            packet.nfqueue.drop()

            # if rejection is enabled on top of prevention port uncreachable packets will be sent back to the scanner.
            if (IPS_IDS.portscan_reject):
                self._portscan_reject(pre_detection_logging, packet, initial_block)

            # if initial block is not set then the current host has already been effectively blocked and does not need
            # to do anything beyond this point.
            if (not initial_block): return

            block_status = self._get_block_status(pre_detection_logging, packet.protocol)

        Log.debug(f'PROXY INITIAL SCANNER | {block_status.name} | {packet.src_ip}:{packet.src_port} > {packet.dst_ip}:{packet.dst_port}.')

        # NOTE: recently removed filter related to ddos engine. if portscan profile is matched and ddos is detected, both
        # will be logged and independantly handled.
        scan_info = IPS_SCAN_RESULTS(initial_block, active_scanner, block_status)
        Log.log(packet, scan_info, engine=IPS.PORTSCAN)

    # makes a decision on connections/ packets on whether it meets the criteria of a portscanner. will return status as need to block (active_block)
    # or initiated block, but still seeing packets from host (scan_detected)
    def _portscan_detect(self, pscan_tracker, packet):
        initial_block, scan_detected = False, False

        # if first time the source ip is seen, it will add ip to dictionary and return immediately
        tracked_ip = pscan_tracker.get(packet.conn.tracked_ip, None)

        # NOTE: this should also act as an effective timout mechanism to re allow packets/ connections from a host
        if (not tracked_ip or fast_time() - tracked_ip['last_seen'] > 15):
            self._add_to_tracker(pscan_tracker, packet, engine=IPS.PORTSCAN)

            return False, False, {}

        if (tracked_ip['active_scanner']):
            tracked_ip['last_seen'] = packet.timestamp

            scan_detected = True

        else:
            tracked_ip['target'][packet.conn.local_port] = 1
            tracked_ip['last_seen'] = packet.timestamp

            # this is the logic to determine whether a host is a scanner or not.
            if (len(tracked_ip['target']) >= 4) or (packet.protocol is PROTO.UDP and not packet.udp_payload):
                tracked_ip['active_scanner'] = True

                initial_block, scan_detected = True, True

            # mapping local port to tcp sequence number for any connection that isnt flagged as active block. this information
            # will be used to retroactively reject scans on ports before being flagged as a scanner.
            if (packet.protocol is PROTO.TCP):
                tracked_ip['pre_detect'][packet.conn.local_port] = packet.seq_number

            elif (packet.protocol is PROTO.UDP):
                tracked_ip['pre_detect'][packet.conn.local_port] = packet.data

        # returning scan tracker to be used by reject to retroactively handle ports before marked as a scanner.
        return initial_block, scan_detected, tracked_ip['pre_detect']

    def _add_to_tracker(self, tracker, packet, *, engine):
        if (engine is IPS.PORTSCAN):
            tracker[packet.conn.tracked_ip] = {
                'last_seen': packet.timestamp, 'active_scanner': False,
                'pre_detect': {}, 'target': {packet.conn.local_port: 1}
            }

        elif (engine is IPS.DDOS):
            tracker[packet.conn.tracked_ip] = {
                'count': 1, 'initial': packet.timestamp, 'last_seen': packet.timestamp
            }

    # using pre detection logging to re create packets prior to being marked as a scanner then calling standard reject
    # to the reject message actually sent
    def _portscan_reject(self, pre_detection_logging, packet, initial_block):
        if (not initial_block):
            self._IPSResponse.prepare_and_send(packet)

        else:
            IPSResponse = self._IPSResponse
            if (packet.protocol is PROTO.TCP):
                for port, seq_num in pre_detection_logging.items():
                    IPSResponse.prepare_and_send(
                        copy(packet).tcp_override(port, seq_num)
                    )

            elif (packet.protocol is PROTO.UDP):
                for port, icmp_payload in pre_detection_logging.items():
                    IPSResponse.prepare_and_send(
                        copy(packet).udp_override(icmp_payload)
                    )

    def _get_block_status(self, pre_detection_logging, protocol):
        open_ports = self._IPS.open_ports

        for port in pre_detection_logging:
            if port in open_ports[protocol]:
                return IPS.MISSED

        return IPS.BLOCKED


if __name__ == '__main__':
    Log.run(
        name=LOG_NAME
    )
    IPS_IDS.run(Log, q_num=2)
