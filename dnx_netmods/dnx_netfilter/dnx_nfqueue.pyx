#!/usr/bin/env python3

cimport cython

from libc.stdio cimport printf

DEF OK  = 0
DEF ERR = 1

DEF NFQ_BUF_SIZE = 4096
DEF MAX_COPY_SIZE = 4016 # 4096(buf) - 80
DEF DEFAULT_MAX_QUEUELEN = 8192

# Socket queue should hold max number of packets of copy size bytes
# formula: DEF_MAX_QUEUELEN * (MaxCopySize+SockOverhead) / 2
DEF SOCK_RCV_SIZE = 1024 * 4796 // 2

# ================================== #
# NetfilterQueue Read/Write lock
# ================================== #
# TODO: confirm this is needed.
#  apparently needed when calling nfq_handle_packet and set_verdict (doesnt sound right to me)
# ---------------------------------- #
cdef pthread_mutex_t NFQlock

pthread_mutex_init(&NFQlock, NULL)


# pre allocating memory for 8 instance.
# instances are created and destroyed sequentially so only one instance will be active at a time.
# this is to make a point to myself that this module could be multithreading within C one day.
@cython.freelist(8)
cdef class CPacket:

    def __cinit__(self):
        self.has_verdict = 0

    cpdef void update_mark(self, uint32_t mark):
        '''Modifies the netfilter mark of the packet.
        '''
        self.packet.mark = mark

    cpdef void accept(self):
        '''Allow the packet to continue to the next table.

        The GIL is released before calling into netfilter.
        '''
        with nogil:
            self._set_verdict(NF_ACCEPT)

    cpdef void drop(self):
        '''Discard the packet.

        The GIL is released before calling into netfilter.
        '''
        with nogil:
            self._set_verdict(NF_DROP)

    cpdef void forward(self, uint_fast16_t queue_num):
        '''Send the packet to a different queue.

        The GIL is released before calling into netfilter.
        '''
        cdef uint32_t forward_to_queue

        with nogil:
            forward_to_queue = queue_num << 16 | NF_QUEUE

            self._set_verdict(forward_to_queue)

    cpdef void repeat(self):
        '''Send the packet back to the top of the current chain.

        The GIL is released before calling into netfilter.
        '''
        with nogil:
            self._set_verdict(NF_REPEAT)

    def get_inint_name(self):

        # cdef object *int_name
        #
        # nfq_get_indev_name(self)

        pass

    def get_outint_name(self):

        # cdef object *int_name
        #
        # nfq_get_outdev_name(self)

        pass

    def get_hw(self):
        '''Return hardware information of the packet.

            hw_info = (in_interface, out_interface, mac_addr, timestamp)
        '''
        cdef:
            (uint32_t, uint32_t, char*, uint32_t) hw_info

            uint32_t in_interface   = nfq_get_indev(self.packet.nld_handle)
            uint32_t out_interface  = nfq_get_outdev(self.packet.nld_handle)
            nfqnl_msg_packet_hw *hw = nfq_get_packet_hw(self.packet.nld_handle)

        if (hw == NULL):
            # nfq_get_packet_hw doesn't work on OUTPUT and PREROUTING chains
            # NOTE: forcing error handling will ensure it is dealt with [properly].
            raise OSError('MAC address not available in OUTPUT and PREROUTING chains')

        hw_info = (
            in_interface, out_interface, <char*>hw.hw_addr, self.packet.timestamp
        )

        return hw_info

    def get_raw_packet(self):
        '''Return layer 3-7 of packet data.
        '''
        return self.packet.data[:<Py_ssize_t>self.packet.len]

    def get_ip_header(self):
        '''Return layer3 of packet data as a tuple converted directly from C struct.
        '''
        cdef (uint8_t, uint8_t, uint16_t, uint16_t, uint16_t,
                uint8_t, uint8_t, uint16_t, uint32_t, uint32_t) ip_header

        cdef IPhdr *iphdr = <IPhdr*>self.packet.data

        ip_header = (
            iphdr.ver_ihl,
            iphdr.tos,
            ntohs(iphdr.tot_len),
            ntohs(iphdr.id),
            ntohs(iphdr.frag_off),
            iphdr.ttl,
            iphdr.protocol,
            ntohs(iphdr.check),
            ntohl(iphdr.saddr),
            ntohl(iphdr.daddr),
        )

        return ip_header

    def get_tcp_header(self):
        '''Return layer4 (TCP) of packet data as a tuple converted directly from C struct.
        '''
        cdef (uint16_t, uint16_t, uint32_t, uint32_t,
                uint8_t, uint8_t, uint16_t, uint16_t, uint16_t) tcp_header

        cdef TCPhdr *tcphdr = <TCPhdr*>&self.packet.data[self.packet.iphdr_len]

        self.protohdr_len = ((tcphdr.th_off >> 4) & 15) * 4

        tcp_header = (
            ntohs(tcphdr.th_sport),
            ntohs(tcphdr.th_dport),
            ntohl(tcphdr.th_seq),
            ntohl(tcphdr.th_ack),
            tcphdr.th_off,
            tcphdr.th_flags,
            ntohs(tcphdr.th_win),
            ntohs(tcphdr.th_sum),
            ntohs(tcphdr.th_urp),
        )

        return tcp_header

    def get_udp_header(self):
        '''Return layer4 (UDP) of packet data as a tuple converted directly from C struct.
        '''
        cdef (uint16_t, uint16_t, uint16_t, uint16_t) udp_header

        cdef UDPhdr *udphdr = <UDPhdr*>&self.packet.data[self.packet.iphdr_len]

        self.protohdr_len = 8

        udp_header = (
            ntohs(udphdr.uh_sport),
            ntohs(udphdr.uh_dport),
            ntohs(udphdr.uh_ulen),
            ntohs(udphdr.uh_sum),
        )

        return udp_header

    def get_icmp_header(self):
        '''Return layer4 (ICMP) of packet data as a tuple converted directly from C struct.

        Calculates protohdr length and unlocks get_payload().
        '''
        cdef (uint8_t, uint8_t) icmp_header

        cdef ICMPhdr *icmphdr = <ICMPhdr*>&self.packet.data[self.packet.iphdr_len]

        self.protohdr_len = 4

        icmp_header = (icmphdr.type, icmphdr.code)

        return icmp_header

    def get_payload(self):
        '''Return payload (>layer4) as Python bytes.

        A call to get a protohdr is required before calling this method.
        '''
        cdef:
            size_t ttl_hdr_len = 20 + self.protohdr_len
            Py_ssize_t payload_len = self.packet.len - ttl_hdr_len

            upkt_buf *payload = &self.packet.data[ttl_hdr_len]

        return payload[:payload_len]

    cdef void set_packet_data(self, PacketData *packet):

        self.packet = packet

    cdef void _set_verdict(self, uint32_t verdict) nogil:
        '''Call appropriate set_verdict function on packet.
        '''
        if (self.has_verdict):
            printf('[C/warning] Verdict already issued for this packet.')

            return

        # ===================================
        # LOCKING ACCESS TO NetfilterQueue
        # prevents nfq packet handler from processing a packet while setting a verdict of another packet.
        # pthread_mutex_lock(&NFQlock)
        # -------------------------
        # NetfilterQueue Processor
        # -------------------------
        if (self.packet.mark):
            nfq_set_verdict2(
                self.packet.q_handle, self.packet.id, verdict, self.packet.mark, self.packet.len, self.packet.data
            )

        else:
            nfq_set_verdict(
                self.packet.q_handle, self.packet.id, verdict, self.packet.len, self.packet.data
            )

        # pthread_mutex_unlock(&NFQlock)
        # UNLOCKING ACCESS TO NetfilterQueue
        # ===================================

        self.has_verdict = 1

# ============================================
# NFQUEUE CALLBACK - PARSE > FORWARD - NO GIL
# ============================================
cdef int32_t nfqueue_rcv(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa, void *q_manager) nogil:

    cdef PacketData dnx_nfqhdr = nfqueue_parse(qh, nfa)

    return nfqueue_forward(qh, nfmsg, nfa, q_manager, dnx_nfqhdr)

# ============================================
# TCP/IP HEADER PARSING - NO GIL
# ============================================
cdef inline PacketData nfqueue_parse(nfq_q_handle *qh, nfq_data *nfa) nogil:

    cdef:
        nfqnl_msg_packet_hdr *nfq_msg_hdr = nfq_get_msg_packet_hdr(nfa)

        PacketData packet

    packet.q_handle   = qh
    packet.nld_handle = nfa
    packet.id         = nfq_msg_hdr.packet_id
    packet.mark       = nfq_get_nfmark(nfa)
    packet.timestamp  = time(NULL)
    packet.len        = nfq_get_payload(nfa, &packet.data)

    iphdr = <IPhdr*>packet.data
    packet.iphdr_len  = (iphdr.ver_ihl & 15) * 4

    return packet

# ============================================
# FORWARDING TO PROXY CALLBACK - GIL ACQUIRED
# ============================================
cdef inline int32_t nfqueue_forward(
        nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa, void *q_manager, PacketData dnx_nfqhdr) with gil:

    # skipping call to __init__
    cdef:
        NetfilterQueue nfqueue = <NetfilterQueue>q_manager
        CPacket cpacket

    cpacket = CPacket.__new__(CPacket)
    cpacket.packet = dnx_nfqhdr

    # (<object>nfqueue.proxy_callback)(cpacket, dnx_nfqhdr.mark)
    nfqueue.proxy_callback(cpacket, dnx_nfqhdr.mark)

    return OK

# ============================================
# NFQUEUE RECV LOOP - NO GIL
# ============================================
# RECV > NFQ_HANDLE > NFQ_CALLBACK > PARSE > PROXY CALLBACK
cdef void process_traffic(nfq_handle *nfqlib_handle) nogil:

    cdef:
        pkt_buf pkt_buffer[NFQ_BUF_SIZE]
        int32_t fd = nfq_fd(nfqlib_handle)

        ssize_t data_len

    while True:
        data_len = recv(fd, pkt_buffer, NFQ_BUF_SIZE, 0)

        if (data_len > 0):
            # ===================================
            # LOCKING ACCESS TO NetfilterQueue
            # prevents verdict from being issues while initially processing the recvd packet
            # TODO: determine if this is ACTUALLY needed vs dumb dumbs saying it is. adjust cfirewall as necessary
            # pthread_mutex_lock(&NFQlock)
            # -------------------------
            # NetfilterQueue Processor
            # -------------------------
            nfq_handle_packet(nfqlib_handle, pkt_buffer, data_len)

            # pthread_mutex_unlock(&NFQlock)
            # UNLOCKING ACCESS TO NetfilterQueue
            # ===================================
        elif (errno != ENOBUFS):
            break


cdef class NetfilterQueue:

    def nf_run(self):
        ''' calls internal C run method to engage nfqueue processes.

        This call will run forever, but the parsing operations will release the GIL and reacquire before returning to
        user callback.
        '''
        with nogil:
            process_traffic(self.nfqlib_handle)

    def nf_set(self, uint_fast16_t queue_num):
        self.nfqlib_handle = nfq_open()
        self.q_handle = nfq_create_queue(self.nfqlib_handle, queue_num, <nfq_callback*>nfqueue_rcv, <void*>self)

        if (self.q_handle == NULL):
            return ERR

        nfq_set_mode(self.q_handle, NFQNL_COPY_PACKET, MAX_COPY_SIZE)
        nfq_set_queue_maxlen(self.q_handle, DEFAULT_MAX_QUEUELEN)
        nfnl_rcvbufsiz(nfq_nfnlh(self.nfqlib_handle), SOCK_RCV_SIZE)

    def set_proxy_callback(self, object func_ref):
        '''Set required reference which will be called after packet data is parsed into C structs.
        '''
        self.proxy_callback = func_ref

    def nf_break(self):
        if (self.q_handle != NULL):
            nfq_destroy_queue(self.q_handle)

        nfq_close(self.nfqlib_handle)
