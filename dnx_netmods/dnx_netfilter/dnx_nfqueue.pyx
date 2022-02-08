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

cdef object user_callback
def set_user_callback(ref):
    '''Set required reference which will be called after packet data is parsed into C structs.'''

    global user_callback

    user_callback = ref

cdef int nf_callback(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa, void *data):

    cdef CPacket packet
    cdef u_int32_t mark

    # skipping call to __init__
    packet = CPacket.__new__(CPacket)

    with nogil:
        mark = packet.parse(qh, nfa)

    user_callback(packet, mark)

    return OK


# pre allocating memory for 8 instance. instances are created and destroyed sequentially so only one instance will be
# active at a time, but this is to make a point to myself that this module could be multithreading within C one day.
@cython.freelist(8)
cdef class CPacket:

    def __cinit__(self):
        self._verdict = False
        self._mark = 0

    cdef u_int32_t parse(self, nfq_q_handle *qh, nfq_data *nfa) nogil:

        self._timestamp = time(NULL)
        self._data_len  = nfq_get_payload(nfa, &self.data)

        self._qh  = qh
        self._nfa = nfa

        self._hdr = nfq_get_msg_packet_hdr(nfa)
        self._id  = ntohl(self._hdr.packet_id)

        # splitting packet by tcp/ip layers
        self._parse()

        # returning mark for more direct access
        return nfq_get_nfmark(nfa)

    cdef inline void _parse(self) nogil:

        self.ip_header = <iphdr*>self.data

        cdef u_int8_t iphdr_len
        cdef u_int8_t protohdr_len = 0

        iphdr_len = (self.ip_header.ver_ihl & 15) * 4
        if (self.ip_header.protocol == IPPROTO_TCP):
            self.tcp_header = <tcphdr*>&self.data[iphdr_len]

            protohdr_len = ((self.tcp_header.th_off >> 4) & 15) * 4

        elif (self.ip_header.protocol == IPPROTO_UDP):
            self.udp_header = <udphdr*>&self.data[iphdr_len]

            protohdr_len = 8

        elif (self.ip_header.protocol == IPPROTO_ICMP):
            self.icmp_header = <icmphdr*>&self.data[iphdr_len]

            protohdr_len = 4

        self._cmbhdr_len = protohdr_len + 20

        self.payload = &self.data[self._cmbhdr_len]

    cdef void verdict(self, u_int32_t verdict) nogil:
        '''Call appropriate set_verdict function on packet.'''

        if (self._verdict):
            printf('[C/warning] Multiple verdicts issued to a single packet.')

            return

        if (self._mark):
            nfq_set_verdict2(
                self._qh, self._id, verdict, self._mark, self._data_len, self.data
            )

        else:
            nfq_set_verdict(
                self._qh, self._id, verdict, self._data_len, self.data
            )

        self._verdict = True

    cpdef update_mark(self, u_int32_t mark):
        '''Modifies the running mark of the packet.'''

        self._mark = mark

    cpdef accept(self):

        with nogil:
            self.verdict(NF_ACCEPT)

    cpdef drop(self):

        with nogil:
            self.verdict(NF_DROP)

    cpdef forward(self, u_int16_t queue_num):
        '''Send instance packet to a different queue.'''

        cdef u_int32_t forward_to_queue

        with nogil:
            forward_to_queue = queue_num << 16 | NF_QUEUE

            self.verdict(forward_to_queue)

    cpdef repeat(self):

        with nogil:
            self.verdict(NF_REPEAT)

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

            hw_info = (
                in_interface, out_interface, mac_addr, timestamp
            )
        '''

        cdef (u_int32_t, u_int32_t, char*, u_int32_t) hw_info

        cdef u_int32_t in_interface  = nfq_get_indev(self._nfa)
        cdef u_int32_t out_interface = nfq_get_outdev(self._nfa)

        self._hw = nfq_get_packet_hw(self._nfa)
        if self._hw == NULL:
            # nfq_get_packet_hw doesn't work on OUTPUT and PREROUTING chains
            # NOTE: forcing error handling will ensure it is dealt with [properly].
            raise OSError('MAC address not available in OUTPUT and PREROUTING chains')

        # casting to bytestring to be compatible with ctuple.
        cdef char *mac_addr = <char*>self._hw.hw_addr

        hw_info = (
            in_interface,
            out_interface,
            mac_addr,
            self._timestamp,
        )

        return hw_info

    def get_raw_packet(self):
        '''Return layer 3-7 of packet data.'''

        return self.data[:<Py_ssize_t>self._data_len]

    def get_ip_header(self):
        '''Return layer3 of packet data as a tuple converted directly from C struct.'''

        cdef (u_int8_t, u_int8_t, u_int16_t, u_int16_t, u_int16_t,
                u_int8_t, u_int8_t, u_int16_t, u_int32_t, u_int32_t) ip_header

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
        '''Return layer4 (TCP) of packet data as a tuple converted directly from C struct.'''

        cdef (u_int16_t, u_int16_t, u_int32_t, u_int32_t,
                u_int8_t, u_int8_t, u_int16_t, u_int16_t, u_int16_t) tcp_header

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
        '''Return layer4 (UDP) of packet data as a tuple converted directly from C struct.'''

        cdef (u_int16_t, u_int16_t, u_int16_t, u_int16_t) udp_header

        udp_header = (
            ntohs(self.udp_header.uh_sport),
            ntohs(self.udp_header.uh_dport),
            ntohs(self.udp_header.uh_ulen),
            ntohs(self.udp_header.uh_sum),
        )

        return udp_header

    def get_icmp_header(self):
        '''Return layer4 (ICMP) of packet data as a tuple converted directly from C struct.'''

        cdef (u_int8_t, u_int8_t) icmp_header

        icmp_header = (
            self.icmp_header.type,
            self.icmp_header.code,
        )

        return icmp_header

    def get_payload(self):
        '''Return payload (>layer4) as Python bytes.'''

        cdef Py_ssize_t payload_len = self._data_len - self._cmbhdr_len

        return self.payload[:payload_len]


cdef class NetfilterQueue:

    cdef void _run(self):

        cdef int fd = nfq_fd(self.h)
        cdef char packet_buf[4096]
        cdef size_t sizeof_buf = sizeof(packet_buf)
        cdef int data_len

        while True:
            with nogil:
                data_len = recv(fd, packet_buf, sizeof_buf, 0)

            if (data_len >= 0):
                nfq_handle_packet(self.h, packet_buf, data_len)

            else:
                if (errno != ENOBUFS):
                    break

    def nf_run(self):
        ''' calls internal C run method to engage nfqueue processes. this call will run forever, but parsing operations
        will release the GIL prior to and acquire before returning to user callback.'''

        self._run()

    def nf_set(self, u_int16_t queue_num):
        self.h = nfq_open()
        self.qh = nfq_create_queue(self.h, queue_num, <nfq_callback*>nf_callback, <void*>self)
        if (self.qh == NULL):
            return ERR

        nfq_set_mode(self.qh, NFQNL_COPY_PACKET, MAX_COPY_SIZE)
        nfq_set_queue_maxlen(self.qh, DEFAULT_MAX_QUEUELEN)
        nfnl_rcvbufsiz(nfq_nfnlh(self.h), SOCK_RCV_SIZE)

    def nf_break(self):
        if (self.qh != NULL):
            nfq_destroy_queue(self.qh)

        nfq_close(self.h)
