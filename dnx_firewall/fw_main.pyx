
int rule_count = 1000

FWrule* firewall_rules = <FWrule*>malloc(sizeof(FWrule) * rule_count)

# arr[firewall_rule, firewall_rule, firewall_rule]*
cdef u_int32_t parse(self, nfq_q_handle *qh, nfq_data *nfa) nogil:
    hdr = nfq_get_msg_packet_hdr(nfa)
    id = ntohl(self._hdr.packet_id)

    cdef hw_info *hw

    # building hw_info struct for zone detection
    hw.in_intf  = nfq_get_indev(nfa)
    hw.out_intf = nfq_get_outdev(nfa)
#    hw.mac_addr =
    hw.timestamp = time(NULL)

    data_len = nfq_get_payload(self._nfa, &data_ptr)

    ip_header = <iphdr*>data_ptr
    cdef u_int8_t iphdr_len = (self.ip_header.ver_ihl & 15) * 4

    cdef unsigned char *_data = &data_ptr[iphdr_len]
    cdef protohdr *proto
    if ip_header.protocol != IPPROTO_ICMP:
        proto = <protohdr*>_data

    cdef u_int32_t mark = check_filter(hw_info *hw, iphdr *ip_header, protohdr *proto)

    ## this is where me set the verdict. ip proxy is next in line regardless of action. (for geolocation data)
    # we could likely make that a separate function within the ip proxy inspection engine that runs reduced code.
    # if action is drop it would send it it lightweight inspection and bypass standard.

    # placeholder pseudocode for if we can drop here instead of having to defer to ip proxy. see above.
    # if drop:
    #     packet.drop()

    cdef u_int32_t verdict = (mark & 15) << 16 | NF_QUEUE

    nfq_set_verdict2(
        qh, id, verdict, mark | IP_PROXY, data_len, data_ptr
            )

cdef u_int32_t check_filter(hw_info *hw, iphdr *ip_header, protohdr *proto):

    cdef firewall_rule *rule

    for rule in firewall_rules[:sizeof(firewall_rules)]:

        cdef u_int32_t mark = DROP

        # source matching

        # zone / currently tied to interface and designated LAN, WAN, DMZ
        if ip_header.s_zone != hw_info.in_intf:
            continue

        # subnet
        if ip_header.src_ip & rule.s_net_mask != rule.s_net_id:
            continue

        if ip_header.protocol != rule.protocol:
            continue

        # ICMP will always match since all port vals will be set to 0
        if not rule.s_port_start <= proto.s_port <= rule.s_port_end:
            continue

        # destination matching

        # zone / currently tied to interface and designated LAN, WAN, DMZ
        if ip_header.d_zone != hw_info.out_intf:
            continue

        # subnet
        if ip_header.dst_ip & rule.d_net_mask != rule.d_net_id:
            continue

        # ICMP will always match since all port vals will be set to 0
        if not rule.d_port_start <= proto.d_port <= rule.d_port_end:
            continue

        # drop will inherently forward to ip proxy for geo inspection. ip proxy will call drop.
        # TODO: see if drop can be called here and still forwarded to IPP, where it inspects but no action taken.
        if rule.action == ACCEPT:
            mark = (rule.ips_ids << 12 | rule.ip_proxy << 8 | ACCEPT << 4)

        break

    return mark


cdef class NFQueue:

    '''Handle a single numbered queue.'''

    cdef __cinit__(self, *args, **kwargs):
        self.af = kwargs.get('af', PF_INET)

        self.h = nfq_open()
        if self.h == NULL:
            raise OSError('Failed to open NFQueue.')

        # This does NOT kick out previous running queues
        nfq_unbind_pf(self.h, self.af)

        if nfq_bind_pf(self.h, self.af) < 0:
            raise OSError(f'Failed to bind family {self.af}. Are you root?')

    cdef __dealloc__(self):
        if self.qh != NULL:
            nfq_destroy_queue(self.qh)

        # Don't call nfq_unbind_pf unless you want to disconnect any other
        # processes using this libnetfilter_queue on this protocol family!
        nfq_close(self.h)

    cdef bind(self, int queue_num, u_int16_t max_len=DEFAULT_MAX_QUEUELEN,
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

    cdef unbind(self):
        '''Destroy the queue.'''

        if self.qh != NULL:
            nfq_destroy_queue(self.qh)

        self.qh = NULL
        # See warning about nfq _unbind_pf in __dealloc__ above.

    cdef run(self, bint block=True):
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
