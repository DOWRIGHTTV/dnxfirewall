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


cdef struct filter_results:
    u_int16_t action
    u_int32_t mark

# MARK PROTOCOL
# 4 bits per, right to left, any not specified is currently undefined
# action is being passed because still want to gather geolocation data on even implicit denies.
# these would not be logged as events, but part of country activity metric.
# ips_ids profile | ip proxy profile| action | module_identifier (corresponds to queue num)

cdef enum:
    NONE:    = 0
    IP_PROXY = 1
    IPS_IDS  = 2

    DROP   = 0
    ACCEPT = 1

cdef class NetfilterQueue:
    cdef nfq_handle *h # Handle to NFQueue library
    cdef nfq_q_handle *qh # A handle to the queue
    cdef u_int16_t af # Address family
    cdef packet_copy_size # Amount of packet metadata + data copied to buffer