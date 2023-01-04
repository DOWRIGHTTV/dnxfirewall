#!/usr/bin/env python3

from __future__ import annotations

from threading import Lock, Thread

from copy import copy
from collections import defaultdict

from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import PROTO, CONN, IPS, ICMP
from dnx_gentools.def_constants import fast_time, RUN_FOREVER, INSPECT_PACKET, DONT_INSPECT_PACKET
from dnx_gentools.def_namedtuples import IPS_SCAN_RESULTS, DDOS_TRACKERS, PSCAN_TRACKERS
from dnx_gentools.standard_tools import inspection_queue

from dnx_iptools.iptables import IPTablesManager
from dnx_iptools.packet_classes import NFQueue

from dnx_secmods.ids_ips.ids_ips_automate import IPSConfiguration
from dnx_secmods.ids_ips.ids_ips_packets import IPSPacket, IPSResponse

from dnx_secmods.ids_ips.ids_ips_log import Log

__all__ = (
    'IDS_IPS',
)


class IDS_IPS(IPSConfiguration, NFQueue):

    _packet_parser = IPSPacket.netfilter_recv

    __slots__ = (
        'ddos_queue',
    )

    def __init__(self):
        self.ddos_queue = inspection_queue()

        super().__init__()

    def _setup(self):
        self.configure()

        IPSResponse.setup(Log, self.__class__.open_ports)

        for i in range(self.DEFAULT_THREAD_COUNT):
            Thread(target=self.inspection_worker, args=(i,)).start()

        for i in range(self.DEFAULT_THREAD_COUNT):
            Thread(target=self.ddos_worker, args=(i,)).start()

    def _pre_inspect(self, packet: IPSPacket) -> bool:
        # permit configured whitelisted hosts (source ip check only)
        if (packet.src_ip in self.ip_whitelist):
            packet.nfqueue.accept()

            return DONT_INSPECT_PACKET

        if (self.ddos_enabled):
            # ddos inspection is independent of pscan and does not invoke action on packets
            self.ddos_queue.add(packet)

        if (self.pscan_enabled and self.open_ports[packet.protocol]):
            return INSPECT_PACKET

        # packet accepted, no inspection
        elif (packet.action is CONN.ACCEPT):
            packet.nfqueue.accept()

        # packet dropped, no inspection
        else:
            packet.nfqueue.drop()

        return DONT_INSPECT_PACKET

    def inspection_worker(self, i: int) -> NoReturn:
        Log.informational(f'[pscan/worker][{i}] inspection thread started')

        inspection_queue_get = self.inspection_queue.get
        pre_inspection = self._pre_inspect

        for _ in RUN_FOREVER:
            packet = inspection_queue_get()

            # fast path for certain conditions
            if not pre_inspection(packet):
                continue

            inspect_portscan(packet)

    def ddos_worker(self, i: int) -> NoReturn:
        Log.informational(f'[ddos/worker][{i}] inspection thread started')

        ddos_queue_get = self.ddos_queue.get

        for _ in RUN_FOREVER:
            packet = ddos_queue_get()

            inspect_ddos(packet)


# =================
# INSPECTION LOGIC
# =================
# global to adjust the unique local port count per host before triggering
PORTSCAN_THRESHOLD = 4

PREPARE_AND_SEND = IPSResponse.prepare_and_send

# conserves resources by not sending packets that don't need to be checked or logged under normal conditions.
# TODO: ensure trackers are getting cleaned of timed out records at some set interval.
pscan_tracker: dict[PROTO, PSCAN_TRACKERS] = {
    proto: PSCAN_TRACKERS(Lock(), {}) for proto in [PROTO.TCP, PROTO.UDP]
}
ddos_tracker: dict[PROTO, DDOS_TRACKERS] = {
    proto: DDOS_TRACKERS(Lock(), {}) for proto in [PROTO.TCP, PROTO.UDP, PROTO.ICMP]
}

# =================
# PSCAN INSPECTION
# =================
def inspect_portscan(packet: IPSPacket) -> None:
    '''drives the overall logic of the portscan detection engine.
    '''
    pscan = pscan_tracker[packet.protocol]
    with pscan.lock:
        initial_block, active_scanner, pre_detection_logging = portscan_detect(pscan.tracker, packet)

    # invoking forwarded verdict for connections from hosts that don't meet active scanner criteria
    if (not active_scanner):

        if (packet.action is CONN.ACCEPT):
            packet.nfqueue.accept()

            Log.debug(f'[pscan/accept] {packet.src_ip}:{packet.src_port} > {packet.dst_ip}:{packet.dst_port}.')

        elif (packet.action is CONN.DROP):
            packet.nfqueue.drop()

            Log.debug(f'[pscan/drop] {packet.src_ip}:{packet.src_port} > {packet.dst_ip}:{packet.dst_port}.')

        return

    elif (IDS_IPS.ids_mode):
        packet.nfqueue.accept()

        block_status = IPS.LOGGED

        Log.debug(f'[pscan/accept] {packet.src_ip}:{packet.src_port} > {packet.dst_ip}:{packet.dst_port}.')

    # dropping the packet then checking for further action.
    elif (IDS_IPS.pscan_enabled):

        packet.nfqueue.drop()

        # if rejection is enabled on top of prevention, port unreachable packets will be sent back to the scanner.
        if (IDS_IPS.pscan_reject):
            portscan_reject(pre_detection_logging, packet, initial_block)

        block_status = get_block_status(pre_detection_logging, packet.protocol)

        Log.debug(f'[pscan/drop] {packet.src_ip}:{packet.src_port} > {packet.dst_ip}:{packet.dst_port}.')

    # making linter happy
    else: block_status = IPS.DISABLED

    # if initial_block is not set, then the current host has already been effectively blocked and the engine
    # does not need to log
    if (initial_block):
        scan_info = IPS_SCAN_RESULTS(initial_block, active_scanner, block_status)

        Log.log(packet, scan_info, engine=IPS.PORTSCAN)

def portscan_detect(tracker: dict, packet: IPSPacket) -> tuple[bool, bool, dict]:
    '''makes a decision for connections/ packets on whether it matches the profile of a port scanner.
    '''
    initial_block, scan_detected = False, False

    # pulling host profile details from tracker
    tracked_ip = tracker.get(packet.tracked_ip, None)

    # first time seeing this flow.
    if (not tracked_ip or fast_time() - tracked_ip['last_seen'] > 15):
        add_to_tracker(tracker, packet, engine=IPS.PORTSCAN)

        return initial_block, scan_detected, {}

    tracked_ip['last_seen'] = packet.timestamp
    if (tracked_ip['active_scanner']):
        scan_detected = True

    else:
        tracked_ip['target'].add(packet.target_port)

        # ====================
        # INSPECTION DECISION
        # ====================
        # this is the logic to determine whether a host is a scanner or not and for mapping local port to the tcp
        # sequence number which will be used to retroactively reject scans on ports prior to the host being flagged.
        # pre detect data will not be inserted for the packet that sets initial block status since we still have the
        # packet data needed to reject normally.
        if (len(tracked_ip['target']) >= PORTSCAN_THRESHOLD) or (packet.protocol is PROTO.UDP and not packet.udp_payload):
            initial_block, scan_detected, tracked_ip['active_scanner'] = True, True, True

        elif (packet.protocol is PROTO.TCP):
            tracked_ip['pre_detect'][packet.target_port].append((packet.src_port, packet.seq_number))

        elif (packet.protocol is PROTO.UDP):
            tracked_ip['pre_detect'][packet.target_port] = (packet.ip_header, packet.udp_header)
        # ====================

    # returning scan tracker to be used by reject to retroactively handle ports before marked as a scanner.
    return initial_block, scan_detected, tracked_ip['pre_detect']

# sending packet response.
# initial blocks will use pre detection log to generate packets for all previously received packets.
def portscan_reject(pre_detection_logging: dict, packet: IPSPacket, initial_block: bool) -> None:
    PREPARE_AND_SEND(packet)

    Log.debug(f'[pscan/reject] {packet.src_ip}:{packet.src_port} > {packet.dst_ip}:{packet.dst_port}.')
    if (not initial_block):
        return

    if (packet.protocol is PROTO.TCP):

        for dst_port, conns in pre_detection_logging.items():

            # some scanners may send to the same port twice
            for src_port, seq_num in conns:
                PREPARE_AND_SEND(copy(packet).tcp_override(dst_port, seq_num))

    elif (packet.protocol is PROTO.UDP):

        for ip_header, udp_header in pre_detection_logging.items():
            PREPARE_AND_SEND(copy(packet).udp_override(ip_header + udp_header))

# checking intersection between pre detection and open port keys.
# the missed_port var will contain any port that was scanned before the host was marked as a scanner.
# if empty, all ports were blocked.
# NOTE: later, this can be used to report on which specific protocol/port was missed
def get_block_status(pre_detection_logging: dict, protocol: PROTO) -> IPS:
    missed_port = pre_detection_logging.keys() & IDS_IPS.open_ports[protocol].keys()
    if (missed_port):
        Log.informational(f'[pscan/missed ports] {missed_port}')

        return IPS.MISSED

    return IPS.BLOCKED

# =================
# DDOS INSPECTION
# =================
def inspect_ddos(packet: IPSPacket) -> None:
    '''drives the overall logic of the ddos detection engine.
    '''
    # filter out everything but icmp echo requests.
    if (packet.protocol is PROTO.ICMP and packet.icmp_type is not ICMP.ECHO): return

    ddos = ddos_tracker[packet.protocol]
    with ddos.lock:
        if not ddos_detected(ddos.tracker, packet): return

    if (IDS_IPS.ids_mode):
        Log.log(packet, IPS.LOGGED, engine=IPS.DDOS)

    elif (IDS_IPS.ddos_enabled):
        IPTablesManager.proxy_add_rule(packet.tracked_ip, packet.timestamp, table='raw', chain='IPS')

        Log.log(packet, IPS.FILTERED, engine=IPS.DDOS)

def ddos_detected(tracker: dict, packet: IPSPacket) -> bool:

    tracked_ip = tracker.get(packet.tracked_ip, None)

    if (not tracked_ip or fast_time() - tracked_ip['last_seen'] > 15):
        add_to_tracker(tracker, packet, engine=IPS.DDOS)

        return False

    tracked_ip['count'] += 1
    tracked_ip['last_seen'] = packet.timestamp

    # if the ddos limit is exceeded and the host is not yet marked, return active ddos and add ip to tracker
    if threshold_exceeded(tracked_ip, packet):

        # this is to suppress log entries for ddos hosts that are being detected by the engine since there is
        # a delay between detection and kernel offload or some packets are already in queue
        if (packet.tracked_ip not in IDS_IPS.fw_rules):
            IDS_IPS.fw_rules[packet.tracked_ip] = packet.timestamp

        return True

    return False


def threshold_exceeded(tracked_ip, packet):
    elapsed_time = packet.timestamp - tracked_ip['initial']

    # filter to prevent checks on hosts with connection length less than 2 seconds which would allow for cps/pps
    # calculation from using fractional values which result in multiplication.
    if (elapsed_time < 2):
        return False

    Log.debug(f'[ddos/cps] {tracked_ip["count"]/elapsed_time}')

    protocol_src_limit = IDS_IPS.ddos_limits[packet.protocol]
    if (tracked_ip['count']/elapsed_time < protocol_src_limit):
        return False

    Log.informational(f'[ddos/cps] {tracked_ip["count"]/elapsed_time}')

    # the tracked host is now marked as engaging in an active d/dos attack.
    return True

def add_to_tracker(tracker, packet, *, engine):
    Log.debug(f'[{engine}/tracker] host {packet.tracked_ip} added.')

    if (engine is IPS.PORTSCAN):
        tracker[packet.tracked_ip] = {
            'last_seen': packet.timestamp, 'active_scanner': False,
            'pre_detect': defaultdict(list), 'target': {packet.target_port}
        }

    elif (engine is IPS.DDOS):
        tracker[packet.tracked_ip] = {
            'count': 1, 'initial': packet.timestamp, 'last_seen': packet.timestamp
        }
