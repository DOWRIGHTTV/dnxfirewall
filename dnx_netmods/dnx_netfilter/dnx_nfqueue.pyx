#!/usr/bin/env python3

cimport cython

from libc.stdio cimport printf

DEF OK  = 0
DEF ERR = 1

DEF MAX_COPY_SIZE = 4016 # 4096(buf) - 80
DEF DEFAULT_MAX_QUEUELEN = 8192

# Socket queue should hold max number of packets of copy size bytes
# formula: DEF_MAX_QUEUELEN * (MaxCopySize+SockOverhead) / 2
DEF SOCK_RCV_SIZE = 1024 * 4796 // 2

# ================================== #
# NetfilterQueue Read/Write lock
# ================================== #
# Must be held during
# ---------------------------------- #
cdef pthread_mutex_t NFQlock

pthread_mutex_init(&NFQlock, NULL)


# pre allocating memory for 8 instance. instances are created and destroyed sequentially so only one instance will be
# active at a time, but this is to make a point to myself that this module could be multithreading within C one day.
@cython.freelist(8)
cdef class CPacket:

    def __cinit__(self):
        self.timestamp = time(NULL)

        self.verdict = 0
        self.mark = 0

    cdef uint32_t parse(self, nfq_q_handle *qh, nfq_data *nfa) nogil:

        self.q_handle = qh
        self.nld_handle = nfa

        self.nfq_msg_hdr = nfq_get_msg_packet_hdr(nfa)

        # filling packet data buffer from netfilter
        self.data_len = nfq_get_payload(nfa, &self.pktdata)

        # splitting the packet by tcp/ip layers
        self._parse()

        # returning mark for more direct access
        return nfq_get_nfmark(nfa)

    cdef inline void _parse(self) nogil:

        cdef:
            size_t iphdr_len
            size_t protohdr_len

        self.ip_header = <IPhdr*>self.pktdata

        iphdr_len = (self.ip_header.ver_ihl & 15) * 4
        if (self.ip_header.protocol == IPPROTO_TCP):
            self.tcp_header = <TCPhdr*>&self.pktdata[iphdr_len]

            protohdr_len = ((self.tcp_header.th_off >> 4) & 15) * 4

        elif (self.ip_header.protocol == IPPROTO_UDP):
            self.udp_header = <UDPhdr*>&self.pktdata[iphdr_len]

            protohdr_len = 8

        elif (self.ip_header.protocol == IPPROTO_ICMP):
            self.icmp_header = <ICMPhdr*>&self.pktdata[iphdr_len]

            protohdr_len = 4

        self.cmbhdr_len = protohdr_len + 20

    cdef void _set_verdict(self, uint32_t verdict) nogil:
        '''Call appropriate set_verdict function on packet.
        '''
        if (self.verdict):
            printf('[C/warning] Verdict already issued for this packet.')

            return

        # ===================================
        # LOCKING ACCESS TO NetfilterQueue
        # prevents nfq packet handler from processing a packet while setting a verdict of another packet.
        pthread_mutex_lock(&NFQlock)
        # -------------------------
        # NetfilterQueue Processor
        # -------------------------
        if (self.mark):
            nfq_set_verdict2(
                self.q_handle, self.nfq_msg_hdr.packet_id, verdict, self.mark, self.data_len, self.pktdata
            )

        else:
            nfq_set_verdict(
                self.q_handle, self.nfq_msg_hdr.packet_id, verdict, self.data_len, self.pktdata
            )

        pthread_mutex_unlock(&NFQlock)
        # UNLOCKING ACCESS TO NetfilterQueue
        # ===================================

        self.verdict = 1

    cpdef void update_mark(self, uint32_t mark):
        '''Modifies the netfilter mark of the packet.
        '''
        self.mark = mark

    cpdef void accept(self):

        with nogil:
            self._set_verdict(NF_ACCEPT)

    cpdef void drop(self):

        with nogil:
            self._set_verdict(NF_DROP)

    cpdef void forward(self, uint16_t queue_num):
        '''Send instance packet to a different queue.

        The GIL is released before applying to packet action.
        '''
        cdef uint32_t forward_to_queue

        with nogil:
            forward_to_queue = queue_num << 16 | NF_QUEUE

            self._set_verdict(forward_to_queue)

    cpdef void repeat(self):
        '''Send instance packet back to the top of current chain.

        The GIL is released before applying to packet action.
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

            uint32_t in_interface   = nfq_get_indev(self.nld_handle)
            uint32_t out_interface  = nfq_get_outdev(self.nld_handle)
            nfqnl_msg_packet_hw *hw = nfq_get_packet_hw(self.nld_handle)

        if (hw == NULL):
            # nfq_get_packet_hw doesn't work on OUTPUT and PREROUTING chains
            # NOTE: forcing error handling will ensure it is dealt with [properly].
            raise OSError('MAC address not available in OUTPUT and PREROUTING chains')

        hw_info = (
            in_interface, out_interface, <char*>hw.hw_addr, self.timestamp
        )

        return hw_info

    def get_raw_packet(self):
        '''Return layer 3-7 of packet data.
        '''
        return self.pktdata[:<Py_ssize_t>self.data_len]

    def get_ip_header(self):
        '''Return layer3 of packet data as a tuple converted directly from C struct.
        '''
        cdef (uint8_t, uint8_t, uint16_t, uint16_t, uint16_t,
                uint8_t, uint8_t, uint16_t, uint32_t, uint32_t) ip_header

        ip_header = (
            self.ip_header.ver_ihl,
            self.ip_header.tos,
            ntohs(self.ip_header.tot_len),
            ntohs(self.ip_header.id),
            ntohs(self.ip_header.frag_off),
            self.ip_header.ttl,
            self.ip_header.protocol,
            ntohs(self.ip_header.check),
            ntohl(self.ip_header.saddr),
            ntohl(self.ip_header.daddr),
        )

        return ip_header

    def get_tcp_header(self):
        '''Return layer4 (TCP) of packet data as a tuple converted directly from C struct.
        '''
        cdef (uint16_t, uint16_t, uint32_t, uint32_t,
                uint8_t, uint8_t, uint16_t, uint16_t, uint16_t) tcp_header

        tcp_header = (
            ntohs(self.tcp_header.th_sport),
            ntohs(self.tcp_header.th_dport),
            ntohl(self.tcp_header.th_seq),
            ntohl(self.tcp_header.th_ack),
            self.tcp_header.th_off,
            self.tcp_header.th_flags,
            ntohs(self.tcp_header.th_win),
            ntohs(self.tcp_header.th_sum),
            ntohs(self.tcp_header.th_urp),
        )

        return tcp_header

    def get_udp_header(self):
        '''Return layer4 (UDP) of packet data as a tuple converted directly from C struct.
        '''
        cdef (uint16_t, uint16_t, uint16_t, uint16_t) udp_header

        udp_header = (
            ntohs(self.udp_header.uh_sport),
            ntohs(self.udp_header.uh_dport),
            ntohs(self.udp_header.uh_ulen),
            ntohs(self.udp_header.uh_sum),
        )

        return udp_header

    def get_icmp_header(self):
        '''Return layer4 (ICMP) of packet data as a tuple converted directly from C struct.
        '''
        cdef (uint8_t, uint8_t) icmp_header

        icmp_header = (
            self.icmp_header.type,
            self.icmp_header.code,
        )

        return icmp_header

    def get_payload(self):
        '''Return payload (>layer4) as Python bytes.
        '''
        cdef:
            Py_ssize_t payload_len = self.data_len - self.cmbhdr_len
            uint8_t *payload = &self.pktdata[self.cmbhdr_len]

        return payload[:payload_len]


cdef class NetfilterQueue:

    def nf_run(self):
        ''' calls internal C run method to engage nfqueue processes.

        This call will run forever, but the parsing operations will release the GIL and reacquire before returning to
        user callback.
        '''
        with nogil:
            self._run()

    def nf_set(self, uint16_t queue_num):
        self.nfq_lib_handle = nfq_open()
        self.q_handle = nfq_create_queue(self.nfq_lib_handle, queue_num, <nfq_callback*>self.nf_callback, <void*>self)
        if (self.q_handle == NULL):
            return ERR

        nfq_set_mode(self.q_handle, NFQNL_COPY_PACKET, MAX_COPY_SIZE)
        nfq_set_queue_maxlen(self.q_handle, DEFAULT_MAX_QUEUELEN)
        nfnl_rcvbufsiz(nfq_nfnlh(self.nfq_lib_handle), SOCK_RCV_SIZE)

    # cdef object user_callback
    def set_proxy_callback(self, func_ref):
        '''Set required reference which will be called after packet data is parsed into C structs.
        '''
        self.proxy_callback = func_ref

    def nf_break(self):
        if (self.q_handle != NULL):
            nfq_destroy_queue(self.q_handle)

        nfq_close(self.nfq_lib_handle)

    cdef void _run(self) nogil:

        cdef:
            char    packet_buf[4096]
            size_t  sizeof_buf = sizeof(packet_buf)
            ssize_t data_len

            int fd = nfq_fd(self.nfq_lib_handle)

        while True:
            data_len = recv(fd, <void*>packet_buf, sizeof_buf, 0)

            if (data_len >= 0):

                # ===================================
                # LOCKING ACCESS TO NetfilterQueue
                # prevents verdict from being issues while initially processing the recvd packet
                pthread_mutex_lock(&NFQlock)
                # -------------------------
                # NetfilterQueue Processor
                # -------------------------
                nfq_handle_packet(self.nfq_lib_handle, <char*>packet_buf, data_len)

                pthread_mutex_unlock(&NFQlock)
                # UNLOCKING ACCESS TO NetfilterQueue
                # ===================================

            elif (errno != ENOBUFS):
                break

    cdef int nf_callback(self, nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa, void *data) with gil:

        cdef:
            CPacket  packet
            uint32_t mark

        # skipping call to __init__
        packet = CPacket.__new__(CPacket)

        with nogil:
            mark = packet.parse(qh, nfa)

        self.proxy_callback(packet, mark)

        return OK
