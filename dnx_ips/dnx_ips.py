#!/usr/bin/env python3

import os, sys
import time
import threading
import traceback

from copy import copy

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_iptools.dnx_interface as interface
from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_standard_tools import dynamic_looper
from dnx_configure.dnx_namedtuples import IPS_WAN_INFO, IPS_SCAN_RESULTS, IPS_IP_INFO, IPS_LOG
from dnx_configure.dnx_file_operations import load_configuration
from dnx_configure.dnx_iptables import IPTableManager

from dnx_iptools.dnx_parent_classes import NFQueue
from dnx_ips.dnx_ips_log import Log
from dnx_ips.dnx_ips_automate import Configuration
from dnx_ips.dnx_ips_packets import IPSPacket, IPSResponse

from dnx_configure.dnx_code_profiler import profiler

LOG_NAME = 'ips'


# TODO: CONVERT PROTOCOL TO ENUMS SINCE WE ARE RESTRICING VIA IPTABLES/NFQUEUE TO ONLY PROTOCOLS WE CARE ABOUT!!!.
class IPS_IDS(NFQueue):
    fw_rules = {}
    ip_whitelist = {}
    open_ports = {PROTO.TCP: {}, PROTO.UDP:{}}
    connection_limits = {}
    broadcast = None

    ddos_prevention = False
    portscan_prevention = False
    portscan_reject = False
    ids_mode = False # TODO: implement this throughout

    ddos_engine_enabled = False
    ps_engine_enabled   = False

    active_ddos = False

    _packet_parser = IPSPacket.netfilter # alternate constructor, but does not return self

    @classmethod
    def _setup(cls):
        Configuration.setup(cls)
        IPSResponse.setup(cls, Log)

        cls.set_proxy_callback(func=Inspect.portscan) # this will get called after parsing is complete.

    # if nothing is enabled the packet will be sent back to iptables for further inspection
    def _pre_check(self, nfqueue):
        if (not self.ddos_engine_enabled and nfqueue.get_mark() == IP_PROXY_DROP):
            Log.debug('packet fast dropped from ip proxy | ddos engine disabled')
            nfqueue.drop()

        elif (not self.inspection_enabled):
            self.forward_packet(nfqueue)
        else:
            return True # marking for inspection

    # NOTE: not returning boolean because the result will need to potentially call multiple threads which is
    # not compatible with inhereted class
    def _pre_inspect(self, packet):
        if (packet.dst_ip == self.broadcast): # TODO: figure this out
            packet.nfqueue.drop()
            return False

        if (self.ddos_engine_enabled and (packet.protocol != PROTO.ICMP or packet.icmp_type == ICMP.ECHO)):
            threading.Thread(target=Inspect.ddos, args=(packet,)).start()

        # this will block packets on behalf of the ip proxy which will not longer directly block.
        # this will allow for ip proxy blocks to still be evaluated for ddos if enabled.
        if (packet.zone == IP_PROXY_DROP):
            packet.nfqueue.drop()

        # will send all other packets to firewall for decision due to portscan engine being disable, but
        # will still allow ddos inspection if enabled
        elif (not self.ps_engine_enabled):
            self.forward_packet(packet.nfqueue)

        # will inspect for portscan if not icmp and not a broadcasted packet
        elif (packet.protocol != PROTO.ICMP):
            return True

        # forward any non matching packets to firewall. icmp and broadcasts primarily
        else:
            self.forward_packet(packet.nfqueue)

        return False # inspection not required

    @staticmethod
    def forward_packet(nfqueue):
        nfqueue.set_mark(SEND_TO_FIREWALL)
        nfqueue.repeat()

    @property
    def inspection_enabled(self):
        if (self.ps_engine_enabled or self.ddos_engine_enabled):
            return True

        return False


class Inspect:
    _IPS = IPS_IDS
    _IPSResponse = IPSResponse
    _status_lock = threading.Lock()

    pscan_tracker = {
        proto: {'lock': threading.Lock(), 'tracker': {}}
        for proto in [PROTO.TCP, PROTO.UDP]
    }
    ddos_tracker = {
        proto: {'lock': threading.Lock(), 'tracker': {}}
        for proto in [PROTO.TCP, PROTO.UDP, PROTO.ICMP]
    }
    active_ddos_hosts = {}
    def __init__(self, packet):
        self._packet = packet

    @classmethod
    def portscan(cls, packet):
        self = cls(packet)
        self._portscan_inspect()

    @classmethod
    def ddos(cls, packet):
        time.sleep(MSEC)
        self = cls(packet)
        self._ddos_inspect()

    # this method drives the overall logic of the ddos detection engine. it will try to conserve resources by not sending packets
    # that dont need to be checked or logged under normal conditions.
    # NOTE: ensure the refactor did not break anything. you know me.
    def _ddos_inspect(self):
        ddos = self.ddos_tracker.get(self._packet.protocol)
        with ddos['lock']:
            if not self._ddos_detected(ddos['tracker']): return

        # this is to supress log entries for ddos hosts that are being detected by the engine, but not blocked
        # this behavior would only happen in informational logging mode without block enabled.
        if self._recently_detected(self._packet.conn.tracked_ip): return

        if (self._IPS.ddos_prevention):
            IPTableManager.proxy_add_rule(self._packet.conn.tracked_ip, table='mangle', chain='IPS')

        # TODO: add entry for ids mode

        Log.log(self._packet, engine=IPS.DDOS)

    def _ddos_detected(self, ddos_tracker):
        detected = False
        tracked_ip = ddos_tracker.get(self._packet.conn.tracked_ip, None)
        if (not tracked_ip):
            self._add_to_tracker(ddos_tracker, engine=IPS.DDOS)
        else:
            new_count = tracked_ip['count'] + 1
            tracked_ip.update(count=new_count, last_seen=self._packet.timestamp)

            # if conn limit exceeded and host is not already marked, returns active ddos and add ip to tracker
            if self._threshhold_exceeded(tracked_ip['initial'], new_count):
                print(f'ACTIVE BLOCK: {self._packet.conn.tracked_ip}')
                # dictionary containing all hosts currently marked as an active ddos attacker
                self.active_ddos_hosts[self._packet.conn.tracked_ip] = 1
                detected = True

        return detected

    def _threshhold_exceeded(self, initial, count):
        protocol_src_limit = self._IPS.connection_limits[self._packet.protocol]
        elapsed_time = self._packet.timestamp - initial
        if (elapsed_time < 2): return False

        connections_per_second = count/elapsed_time
        if (connections_per_second < protocol_src_limit): return False

        # host is now considered active DDOS
        Log.debug(f'CPS: {connections_per_second}')
        return True

    @dynamic_looper
    def _ddos_timeout(self, tracked_ip, ddos_tracker):
        # if marked as an active ddos host, will timeout the conn
        # since we will be dropping all subsequent conn attempts at the kernel level
        if self.active_ddos_hosts.pop(tracked_ip, None): return 'break'

        # if tracked ip hasnt been seen for 10 seconds, it will be removed from the ddos tracker and thread will close
        tracked_connection = ddos_tracker.get(tracked_ip, None)
        last_seen = tracked_connection.get('last_seen')
        if (time.time() - last_seen >= 10):
            ddos_tracker.pop(tracked_ip)
            Log.debug(f'DDOS TIMED OUT CONN: {tracked_ip}')

            return 'break'

        return 5.1

    # this method drives the overall logic of the portscan detection engine. it will try to conserve resources but not sending packets
    # that dont need to be checked or logged under normal conditions.
    def _portscan_inspect(self):
        pscan = self.pscan_tracker.get(self._packet.protocol)
        with pscan['lock']:
            initial_block, active_scanner, pre_detection_logging = self._portscan_detect(pscan['tracker'])
        if (not active_scanner):
            Log.informational(f'PROXY ACCEPT | {self._packet.src_ip}:{self._packet.src_port} > {self._packet.dst_ip}:{self._packet.dst_port}.')
            self._IPS.forward_packet(self._packet.nfqueue)

            return

        if (self._IPS.portscan_prevention):
            if (self._IPS.ids_mode):
                self._IPS.forward_packet(self._packet.nfqueue)
                block_status = IPS.LOGGED
            else:
                self._packet.nfqueue.drop()

            if (self._IPS.portscan_reject):
                self._portscan_reject(pre_detection_logging)

            if (pre_detection_logging):
                block_status = self._get_block_status(pre_detection_logging)

                Log.informational(f'PROXY ACTIVE SCANNER DROP {self._packet.src_ip}:{self._packet.src_port} > {self._packet.dst_ip}:{self._packet.dst_port}.')
                if (not self.active_ddos):
                    scan_info = IPS_SCAN_RESULTS(initial_block, active_scanner, block_status)
                    Log.log(self._packet, scan_info, engine=IPS.PORTSCAN)

                else: # NOTE: for testing purposes only
                    Log.informational('ACTIVE DDOS WHEN ATTEMPTING TO LOG PORTSCAN, LOG HAULTED.')

    # makes a decision on connections/ packets on whether it meets the criteria of a portscanner. will return status as need to block (active_block)
    # or initiated block, but still seeing packets from host (scan_detected)
    def _portscan_detect(self, pscan_tracker):
        initial_block, scan_detected, pre_detection_logging = False, False, None

        if self.is_active_scanner(pscan_tracker, self._packet.conn.tracked_ip):
            pscan_tracker[self._packet.conn.tracked_ip]['last_seen'] = self._packet.timestamp
            # initial_block, scan_detected, pre_detection_logging
            return False, True, {}

        # if first time the source ip is seen, it will add ip to dictionary
        tracked_ip = pscan_tracker.get(self._packet.conn.tracked_ip, None)
        if (not tracked_ip):
            self._add_to_tracker(pscan_tracker, engine=IPS.PORTSCAN)
        else:
            tracked_ip['last_seen'] = self._packet.timestamp
            tracked_ip['target'][self._packet.conn.local_port] = 1
            # this is the logic to determine whether a host is a scanner or not.
            if ((len(tracked_ip['target']) >= 4) or (self._packet.protocol is PROTO.UDP and not self._packet.udp_payload)):
                tracked_ip['active_scanner'] = True
                pre_detection_logging = tracked_ip.get('pre_detect')
                initial_block = True
                scan_detected = True

            # mapping local port to tcp sequence number for any connection that isnt flagged as active block. this information
            # will be used to retroactively reject scans on ports before being flagged as a scanner.
            if (self._packet.protocol is PROTO.TCP):
                tracked_ip['pre_detect'][self._packet.conn.local_port] = self._packet.seq_number
            elif (self._packet.protocol is PROTO.UDP):
                tracked_ip['pre_detect'][self._packet.conn.local_port] = self._packet.ip_header_plus_data

        # returning scan tracker to be used by reject to retroactively handle ports before marked as a scanner.
        return initial_block, scan_detected, pre_detection_logging

    def _add_to_tracker(self, tracker, *, engine):
        packet = self._packet
        if (engine is IPS.PORTSCAN):
            tracker[packet.conn.tracked_ip] = {
                'last_seen': packet.timestamp, 'active_scanner': False,
                'pre_detect': {}, 'target': {packet.conn.local_port: 1}
            }
        elif(engine is IPS.DDOS):
            tracker[packet.conn.tracked_ip] = {
                'count': 1, 'initial': packet.timestamp, 'last_seen': packet.timestamp
            }
        threading.Thread(
            target=getattr(self, f'_{engine.name.lower()}_timeout'),
            args=(packet.conn.tracked_ip, tracker)
        ).start()

    def is_active_scanner(self, host_tracker, tracked_ip):
        tracked = host_tracker.get(tracked_ip)
        if (not tracked):
            return False

        return tracked['active_scanner']

    # using pre detection logging to re create packets prior to being marked as a scanner then calling standard reject
    # to the reject message actually sent
    def _portscan_reject(self, pre_detection_logging):
        if (not pre_detection_logging):
            self._IPSResponse.prepare_and_send(self._packet)
        else:
            if (self._packet.protocol == PROTO.TCP):
                for port, seq_num in pre_detection_logging.items():
                    self._IPSResponse.prepare_and_send(
                        copy(self._packet).tcp_override(port, seq_num)
                    )

            elif (self._packet.protocol == PROTO.UDP):
                for port, icmp_payload in pre_detection_logging.items():
                    self._IPSResponse.prepare_and_send(
                        copy(self._packet).udp_override(icmp_payload)
                    )

    @dynamic_looper
    # this will timeout the portscanner host from the tracker once activity has not been seen for 10 seconds.
    def _portscan_timeout(self, tracked_ip, scan_tracker):
        last_seen = scan_tracker.get(tracked_ip)['last_seen']
        if (time.time() - last_seen < 10): return 5.1

        scan_tracker.pop(tracked_ip, None)
        print(f'PORTSCAN TIMED OUT CONN: {tracked_ip}')
        return 'break'

    def _get_block_status(self, pre_detection_logging):
        for port in pre_detection_logging:
            if port in self._IPS.open_ports[self._packet.protocol]:
                return IPS.MISSED

        return IPS.BLOCKED

    # TODO: validate the thread timer is actually running and calling the method/ the object is being removed
    # NOTE: will this recently detected set work across instances?
    # from the set. maybe make locks per protocol??
    def _recently_detected(self, tracked_ip, recently_detected=set()):
        with self._status_lock:
            if (tracked_ip in recently_detected): return True

            recently_detected.add(tracked_ip)
            threading.Timer(
                TEN_SEC, self._remove_recently_detected_host, args=(tracked_ip, recently_detected)
            ).start()

            return False

    def _remove_recently_detected_host(self, tracked_ip, recently_detected):
        recently_detected.remove(tracked_ip)

    @property
    def active_ddos(self):
        if (self.active_ddos_hosts):
            self._IPS.active_ddos = True
            return True

        self._IPS.active_ddos = False
        return False


if __name__ == '__main__':
    Log.run(
        name=LOG_NAME,
        verbose=VERBOSE,
        root=ROOT
    )
    IPS_IDS.run(Log, q_num=2)
