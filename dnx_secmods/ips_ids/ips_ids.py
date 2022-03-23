#!/usr/bin/env python3

from __future__ import annotations

import threading

from copy import copy
from collections import defaultdict

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_enums import *
from dnx_gentools.def_namedtuples import IPS_SCAN_RESULTS, DDOS_TRACKERS, PSCAN_TRACKERS
from dnx_routines.configure.iptables import IPTablesManager

from dnx_iptools.packet_classes import NFQueue
from dnx_secmods.ips_ids.ips_ids_automate import Configuration
from dnx_secmods.ips_ids.ips_ids_packets import IPSPacket, IPSResponse

from dnx_secmods.ips_ids.ips_ids_log import Log

__all__ = (
    'run', 'IPS_IDS'
)

LOG_NAME = 'ips'

# global to adjust the unique local port count per host before triggering
PORTSCAN_THRESHOLD = 4


class IPS_IDS(NFQueue):
    fw_rules: ClassVar[dict] = {}
    connection_limits: ClassVar[dict] = {}
    ip_whitelist: ClassVar[dict] = {}
    open_ports: ClassVar[dict[PROTO, dict]] = {
        PROTO.TCP: {},
        PROTO.UDP: {}
    }

    ddos_prevention: ClassVar[int] = 0
    portscan_prevention: ClassVar[int] = 0
    portscan_reject: ClassVar[int] = 0
    ids_mode: ClassVar[int] = 0  # TODO: implement this throughout

    ddos_engine_enabled: ClassVar[int] = 0
    ps_engine_enabled: ClassVar[int] = 0
    all_engines_enabled: ClassVar[int] = 0

    _packet_parser = IPSPacket.netfilter_recv

    def _setup(self):
        self.__class__.set_proxy_callback(func=Inspect.portscan)

        Configuration.setup(self.__class__)
        IPSResponse.setup(Log, self.__class__)

        Log.notice(f'{self.__class__.__name__} initialization complete.')

    def _pre_inspect(self, packet: IPSPacket) -> bool:
        # permit configured whitelisted hosts (source ip check only)
        if (packet.src_ip in self.ip_whitelist):
            packet.nfqueue.accept()

            return False

        # CONN.ACCEPT or CONN.INSPECT
        if (self.all_engines_enabled):

            # ddos inspection is independent of pscan and does not invoke action on packets
            threading.Thread(target=Inspect.ddos, args=(packet,)).start()

            # pscan engine is the primary engine which can invoke control, so the decision will be deferred until after
            # inspection has taken place.
            if (packet.protocol is not PROTO.ICMP):
                return True

        # ip proxy accept > ddos inspect.
        # must invoke packet action here since the packet will not be sent through the pscan engine so a packet decision
        # will not be made unless we do it here.
        elif (self.ddos_engine_enabled):

            if (packet.action is CONN.ACCEPT):
                packet.nfqueue.accept()

            else:
                packet.nfqueue.drop()

            threading.Thread(target=Inspect.ddos, args=(packet,)).start()

        # ip proxy accept > portscan inspect if tcp or udp. icmp will be forwarded without inspection since the
        # protocol is not compatible with server ports.
        elif (self.ps_engine_enabled):

            # notify tcp/udp to be inspected by portscan engine
            if (packet.protocol is not PROTO.ICMP):
                return True

            # icmp will just be accepted here as long as the packet wasn't received from the INPUT chain since
            # nothing have objected to it. default return of do not inspect will handle this condition.
            elif (packet.action is CONN.ACCEPT):
                packet.nfqueue.accept()

            # this will drop the packet so it doesn't become orphaned in the kernel or get accepted and hit the
            # wan interface. this will match CONN.DROP or CONN.INSPECT, both having same packet action, but
            # different inspection logic.
            else:
                packet.nfqueue.drop()

        # no inspection, packet accepted. default action no inspect applied
        elif packet.action is CONN.ACCEPT:
            packet.nfqueue.accept()

        # no inspection, but action is drop or inspect. default no inspect applied.
        else:
            packet.nfqueue.drop()

        return False


# TODO: ensure trackers are getting cleaned of timed out records at some set interval.
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
    # NOTE: not passing in _IPS object since it doesn't seem to be worth it. maybe can for consistency though.
    def ddos(cls, packet):
        self = cls()
        self._ddos_inspect(packet)

    # this method drives the overall logic of the ddos detection engine. it will try to conserve resources by not
    # sending packets that don't need to be checked or logged under normal conditions.
    def _ddos_inspect(self, packet):
        # filter to make only icmp echo requests checked. This used to be done by the IP proxy, but after some
        # optimizations it is much more suited here.
        if (packet.protocol is PROTO.ICMP and packet.icmp_type is not ICMP.ECHO): return

        ddos = self.ddos_tracker[packet.protocol]
        with ddos.lock:
            if not self._ddos_detected(ddos.tracker, packet): return

        if (self._IPS.ids_mode):
            Log.log(packet, IPS.LOGGED, engine=IPS.DDOS)

        elif (self._IPS.ddos_prevention):
            IPTablesManager.proxy_add_rule(packet.tracked_ip, packet.timestamp, table='raw', chain='IPS')

            Log.log(packet, IPS.FILTERED, engine=IPS.DDOS)

    def _ddos_detected(self, ddos_tracker, packet):
        tracked_ip = ddos_tracker.get(packet.tracked_ip, None)
        if (not tracked_ip or fast_time() - tracked_ip['last_seen'] > 15):
            self._add_to_tracker(ddos_tracker, packet, engine=IPS.DDOS)

        else:
            tracked_ip['count'] += 1
            tracked_ip['last_seen'] = packet.timestamp

            # if the conn limit is exceeded and the host is not yet marked, return active ddos and add ip to tracker
            if self._threshold_exceeded(tracked_ip, packet):

                # this is to suppress log entries for ddos hosts that are being detected by the engine since there is
                # a delay between detection and kernel offload or some packets are already in queue
                if (packet.tracked_ip not in self._IPS.fw_rules):
                    self._IPS.fw_rules[packet.tracked_ip] = packet.timestamp

                    return True

        return False

    def _threshold_exceeded(self, tracked_ip, packet):
        elapsed_time = packet.timestamp - tracked_ip['initial']

        # filter to ensure tracked host's initial packet was received 2 seconds or more ago. this is needed to
        # prevent the cps/pps calculation from calculating average on fractional values which result in multiplication
        # instead of division causing the result to be greater than the total count itself.
        if (elapsed_time < 2): return False

        # NOTE: temporary while in WIP
        Log.debug(f'[ddos/cps] {tracked_ip["count"]/elapsed_time}')

        protocol_src_limit = self._IPS.connection_limits[packet.protocol]
        if (tracked_ip['count']/elapsed_time < protocol_src_limit): return False

        # host is now marked as engaging in active d/dos attack.
        Log.informational(f'[ddos/cps] {tracked_ip["count"]/elapsed_time}')

        return True

    # this method drives the overall logic of the portscan detection engine. it will try to conserve resources but
    # not sending packets that don't need to be checked or logged under normal conditions.
    def _portscan_inspect(self, ips_ids: IPS_IDS_T, packet: IPSPacket):
        pscan = self.pscan_tracker[packet.protocol]
        with pscan.lock:
            initial_block, active_scanner, pre_detection_logging = self._portscan_detect(pscan.tracker, packet)

        # accepting connections from hosts that don't meet active scanner criteria
        if (not active_scanner):

            # CONN.INSPECT was dropped in pre_inspect and only needed to inspect for profiling purposes
            if (packet.action is not CONN.INSPECT):
                packet.nfqueue.accept()

                Log.debug(f'[pscan/accept] {packet.src_ip}:{packet.src_port} > {packet.dst_ip}:{packet.dst_port}.')

            # for tshooting purposes and will likely leave since this is valuable information for a user if they are
            # trying to see what is going on with their ips configurations if things are not working as intended.
            else:
                Log.debug(f'[pscan/profile] {packet.src_ip}:{packet.src_port} > {packet.dst_ip}:{packet.dst_port}.')

            return

        # prevents connections from being blocked, but will be logged.
        # NOTE: this may be noisy and log multiple times per single scan.
        # TODO: validate.
        elif (ips_ids.ids_mode):

            # CONN.INSPECT was dropped in pre_inspect and only needed to inspect for profiling purposes
            if (packet.action is not CONN.INSPECT):
                packet.nfqueue.accept()

            block_status = IPS.LOGGED

        # dropping the packet then checking for further action.
        elif (ips_ids.portscan_prevention):

            # CONN.INSPECT was dropped in pre_inspect and only needed to inspect for profiling purposes
            if (packet.action is not CONN.INSPECT):
                packet.nfqueue.drop()

            # if rejection is enabled on top of prevention, port unreachable packets will be sent back to the scanner.
            if (ips_ids.portscan_reject):
                self._portscan_reject(pre_detection_logging, packet, initial_block)

            # if initial_block is not set, then the current host has already been effectively blocked and the engine
            # does not need to do anything beyond this point.
            if (not initial_block): return

            block_status = self._get_block_status(pre_detection_logging, packet.protocol)

        # NOTE: recently removed filter related to ddos engine. if portscan profile is matched and ddos is detected,
        # both will be logged and independently handled.
        scan_info = IPS_SCAN_RESULTS(initial_block, active_scanner, block_status)
        Log.log(packet, scan_info, engine=IPS.PORTSCAN)

    # makes a decision on connections/ packets on whether it meets the criteria of a port scanner. will return status
    # as need to block (active_block) or initiated block, but still seeing packets from host (scan_detected)
    def _portscan_detect(self, pscan_tracker, packet) -> tuple[bool, bool, dict]:
        initial_block, scan_detected = False, False

        # pulling host profile details from tracker
        tracked_ip = pscan_tracker.get(packet.tracked_ip, None)

        # NOTE: this should also act as an effective timeout mechanism to re allow packets/ connections from a host
        if (not tracked_ip or fast_time() - tracked_ip['last_seen'] > 15):
            self._add_to_tracker(pscan_tracker, packet, engine=IPS.PORTSCAN)

            return False, False, {}

        tracked_ip['last_seen'] = packet.timestamp
        if (tracked_ip['active_scanner']):
            scan_detected = True

        else:
            tracked_ip['target'].add(packet.target_port)

            # ===================================================================================================
            # this is the logic to determine whether a host is a scanner or not and for mapping local port to tcp
            # sequence number which will be used to retroactively reject scans on ports prior to the host being
            # flagged. pre detect data will not be inserted for packet that sets initial block status since we still
            # have the packet data needed to respond.
            if (len(tracked_ip['target']) >= PORTSCAN_THRESHOLD) or (packet.protocol is PROTO.UDP and not packet.udp_payload):
                initial_block, scan_detected, tracked_ip['active_scanner'] = True, True, True

            elif (packet.protocol is PROTO.TCP):
                tracked_ip['pre_detect'][packet.target_port].append((packet.src_port, packet.seq_number))

            elif (packet.protocol is PROTO.UDP):
                tracked_ip['pre_detect'][packet.target_port] = (packet.ip_header, packet.udp_header)

            # ===================================================================================================

        # returning scan tracker to be used by reject to retroactively handle ports before marked as a scanner.
        return initial_block, scan_detected, tracked_ip['pre_detect']

    # NOTE: target is now a set. I believe at one point the values had a purpose, but now they do not. a set
    # reduces complexity and performs the same.
    def _add_to_tracker(self, tracker, packet, *, engine):
        if (engine is IPS.PORTSCAN):
            tracker[packet.tracked_ip] = {
                'last_seen': packet.timestamp, 'active_scanner': False,
                'pre_detect': defaultdict(list), 'target': {packet.target_port}
            }

        elif (engine is IPS.DDOS):
            tracker[packet.tracked_ip] = {
                'count': 1, 'initial': packet.timestamp, 'last_seen': packet.timestamp
            }

    # sending packet response.
    # if initial block is set, then pre detection logging will be used to generate responses for packets prior to being
    # flagged a scanner.
    def _portscan_reject(self, pre_detection_logging, packet, initial_block):
        self._IPSResponse.prepare_and_send(packet)

        if (initial_block):

            ips_response = self._IPSResponse

            if (packet.protocol is PROTO.TCP):

                for dst_port, conns in pre_detection_logging.items():

                    # some scanners may send to the same port twice
                    for src_port, seq_num in conns:
                        ips_response.prepare_and_send(
                            copy(packet).tcp_override(dst_port, src_port, seq_num)
                        )

            elif (packet.protocol is PROTO.UDP):

                for ip_header, udp_header in pre_detection_logging.items():
                    ips_response.prepare_and_send(
                        copy(packet).udp_override(ip_header, udp_header)
                    )

    # checking intersection between pre detection and open port keys.
    # missed_port will contain any port that was scanned before the host was marked as scanner.
    # if empty, all ports were blocked.
    # NOTE: later, this can be used to report on which specific protocol/port was missed
    def _get_block_status(self, pre_detection_logging: dict, protocol: PROTO) -> IPS:
        missed_port = pre_detection_logging.keys() & self._IPS.open_ports[protocol].keys()
        if (missed_port):
            Log.informational(f'[pscan/missed ports] {missed_port}')

            return IPS.MISSED

        return IPS.BLOCKED

def run():
    IPS_IDS.run(Log, q_num=Queue.IPS_IDS)


if (INIT_MODULE == LOG_NAME):
    Log.run(
        name=LOG_NAME
    )
