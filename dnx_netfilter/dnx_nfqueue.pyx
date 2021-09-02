#!/usr/bin/env python3

'''
This is a derivative work based on python-netfilterqueue.

see: SOURCE-LICENSE.txt (MIT), https://github.com/kti/python-netfilterqueue

As a derived work, see: DERIVATIVE-LICENSE.txt (AGPL3)
'''

import socket

# Constants for module users
cdef int COPY_NONE = 0
cdef int COPY_META = 1
cdef int COPY_PACKET = 2

cdef u_int16_t DEFAULT_MAX_QUEUELEN = 1024
cdef u_int16_t MaxPacketSize = 0xFFFF

# buffer size - metadata size
cdef u_int16_t MaxCopySize = 4096 - 80

# Socket queue should hold max number of packets of copy size bytes
# formula: DEF_MAX_QUEUELEN * (MaxCopySize+SockOverhead) / 2
cdef u_int32_t SockRcvSize = 1024 * 4796 // 2

cdef object user_callback
def set_user_callback(ref):
    '''Set required reference which will be called after packet data is parsed into C structs.'''

    global user_callback

    user_callback = ref

cdef int nf_callback(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa, void *data):

    cdef u_int32_t mark

    packet = CPacket()
    with nogil:
        mark = packet.parse(qh, nfa)

    user_callback(packet, mark)

    return 1


cdef class CPacket:

    def __cinit__(self):
        self._verdict = False
        self._mark = 0

    cdef u_int32_t parse(self, nfq_q_handle *qh, nfq_data *nfa) nogil:

        self._timestamp = time(NULL)
        self._mark = nfq_get_nfmark(nfa)
        self._data_len = nfq_get_payload(nfa, &self.data)

        self._qh = qh
        self._nfa = nfa

        self._hdr = nfq_get_msg_packet_hdr(nfa)
        self._id = ntohl(self._hdr.packet_id)

        # splitting packet by tcp/ip layers
        self._parse()

        # returning mark for more direct access
        return self._mark

    cdef void _parse(self) nogil:

        self.ip_header = <iphdr*>self.data

        cdef u_int8_t iphdr_len
        cdef u_int8_t protohdr_len = 0

        iphdr_len = (self.ip_header.ver_ihl & 15) * 4

        cdef unsigned char *_data = &self.data[iphdr_len]

        if (self.ip_header.protocol == IPPROTO_TCP):
            self.tcp_header = <tcphdr*>_data

            protohdr_len = ((self.tcp_header.th_off >> 4) & 15) * 4

        elif (self.ip_header.protocol == IPPROTO_UDP):
            self.udp_header = <udphdr*>_data

            protohdr_len = 8

        elif (self.ip_header.protocol == IPPROTO_ICMP):
            self.icmp_header = <icmphdr*>_data

            protohdr_len = 4

        self._cmbhdr_len = protohdr_len + 20

        self.payload = &self.data[self._cmbhdr_len]

    cdef void verdict(self, u_int32_t verdict):
        '''Call appropriate set_verdict function on packet.'''

        if self._verdict:
            raise RuntimeWarning('Verdict already given for this packet.')

        if self._mark:
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
        '''Accept the packet.'''

        self.verdict(NF_ACCEPT)

    cpdef drop(self):
        '''Drop the packet.'''

        self.verdict(NF_DROP)

    cpdef forward(self, u_int16_t queue_num):
        '''Send the packet to a different queue.'''

        cdef u_int32_t forward_to_queue

        forward_to_queue = queue_num << 16 | NF_QUEUE

        self.verdict(forward_to_queue)

    cpdef repeat(self):
        '''Repeat the packet.'''

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

        cdef (u_int32_t, u_int32_t, char*, double) hw_info

        cdef u_int32_t in_interface = nfq_get_indev(self._nfa)
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

    def get_udp_header(self):
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
    '''Handle a single numbered queue.'''

    def __cinit__(self, *args, **kwargs):
        self.af = kwargs.get('af', PF_INET)

        self.h = nfq_open()
        if self.h == NULL:
            raise OSError('Failed to open NFQueue.')

        # This does NOT kick out previous running queues
        nfq_unbind_pf(self.h, self.af)

        if nfq_bind_pf(self.h, self.af) < 0:
            raise OSError(f'Failed to bind family {self.af}. Are you root?')

    def __dealloc__(self):
        if self.qh != NULL:
            nfq_destroy_queue(self.qh)

        # Don't call nfq_unbind_pf unless you want to disconnect any other
        # processes using this libnetfilter_queue on this protocol family!
        nfq_close(self.h)

    def bind(self, int queue_num, u_int16_t max_len=DEFAULT_MAX_QUEUELEN,
            u_int8_t mode=NFQNL_COPY_PACKET, u_int16_t range=MaxPacketSize, u_int32_t sock_len=SockRcvSize):
        '''Create and bind to a new queue.'''

        cdef unsigned int newsiz

        self.qh = nfq_create_queue(self.h, queue_num, <nfq_callback*>nf_callback, <void*>self)
        if self.qh == NULL:
            raise OSError(f'Failed to create queue {queue_num}')

        if range > MaxCopySize:
            range = MaxCopySize

        if nfq_set_mode(self.qh, mode, range) < 0:
            raise OSError('Failed to set packet copy mode.')

        nfq_set_queue_maxlen(self.qh, max_len)

        newsiz = nfnl_rcvbufsiz(nfq_nfnlh(self.h), sock_len)
        if newsiz != sock_len * 2:
            raise RuntimeWarning(f'Socket rcvbuf limit is now {newsiz}, requested {sock_len}.')

    def unbind(self):
        '''Destroy the queue.'''

        if self.qh != NULL:
            nfq_destroy_queue(self.qh)

        self.qh = NULL
        # See warning about nfq _unbind_pf in __dealloc__ above.

    def run(self, bint block=True):
        '''Accept packets using recv.'''

        cdef int fd = nfq_fd(self.h)
        cdef char buf[4096]
        cdef int rv
        cdef int recv_flags = 0

        while True:
            with nogil:
                rv = recv(fd, buf, sizeof(buf), recv_flags)

            if (rv >= 0):
                nfq_handle_packet(self.h, buf, rv)

            else:
                if errno != ENOBUFS:
                    break
