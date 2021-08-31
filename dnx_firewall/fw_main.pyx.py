cdef struct FWrule:
    # source
    u_int8_t protocol
    u_int8_t s_zone
    u_int32_t s_net_id
    u_int8_t s_net_mask
    u_int16_t s_port_start
    u_int16_t s_port_end

    #desitnation
    u_int8_t d_zone
    u_int32_t d_net_id
    u_int8_t d_net_mask
    u_int16_t d_port_start
    u_int16_t d_port_end

    # profiles - forward traffic only
    u_int8_t action # 0 drop, 1 accept (if profile set, and action is allow, action will be changed to forward)
    u_int8_t ip_proxy # 0 off, > 1 profile number
    u_int8_t ips_ids # 0 off, 1 on

cdef struct hw_info:
    u_int32_t, in_intf
    u_int32_t out_intf
    u_int8_t[6] mac_addr
    double timestamp

# cython define
cdef struct iphdr:
    u_int8_t  ver_ihl
    u_int8_t  tos
    u_int16_t tot_len
    u_int16_t id
    u_int16_t frag_off
    u_int8_t  ttl
    u_int8_t  protocol
    u_int16_t check
    u_int32_t saddr
    u_int32_t daddr

cdef struct protohdr:
    u_int16_t s_port
    u_int16_t d_port

cdef enum:
    NONE:    = 0
    IP_PROXY = 1
    IPS_IDS  = 2

    DROP   = 0
    ACCEPT = 1

# MARK PROTOCOL
# 4 bits per, right to left, any not specified is currently undefined
# action is being passed because still want to gather geolocation data on even implicit denies.
# these would not be logged as events, but part of country activity metric.
# ips_ids profile | ip proxy profile| action | queue-num

u_int8_t IP_PROXY = 1

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

cdef u_int32_t check_filter(hw_info *hw, iphdr *ip_header, protohdr *proto):

    cdef firewall_rule rule

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
