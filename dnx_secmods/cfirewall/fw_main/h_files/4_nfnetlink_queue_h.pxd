cdef extern from "linux/netfilter/nf_conntrack_common.h" nogil:
    # connection state tracking for netfilter. this is separated from, but required by, the
    # NAT layer. it can also be used by an iptables extension.
    enum: # ip_conntrack_info:
        # part of an established connection (either direction).
        IP_CT_ESTABLISHED

        # like NEW, but related to an existing connection, or ICMP error (in either direction).
        IP_CT_RELATED

        # started a new connection to track (only IP_CT_DIR_ORIGINAL); may be a retransmission.
        IP_CT_NEW

        # >= this indicates reply direction
        IP_CT_IS_REPLY

        IP_CT_ESTABLISHED_REPLY
        IP_CT_RELATED_REPLY
        IP_CT_NEW_REPLY
        # number of distinct IP_CT types (no NEW in reply dirn).
        IP_CT_NUMBER

cdef extern from "linux/netfilter/nfnetlink.h" nogil:
    # General form of address family dependent message.
    struct nfgenmsg:
        uint8_t     nfgen_family        # AF_xxx
        uint8_t     version             # nfnetlink version
        uint16_t    res_id              # resource id

cdef extern from "linux/netfilter/nfnetlink_queue.h" nogil:
    enum nfqnl_msg_types:
        NFQNL_MSG_PACKET                # packet from kernel to userspace
        NFQNL_MSG_VERDICT               # verdict from userspace to kernel
        NFQNL_MSG_CONFIG                # connect to a particular queue

        NFQNL_MSG_MAX

    struct nfqnl_msg_packet_hdr:
        uint32_t    packet_id
        uint16_t    hw_protocol
        uint8_t     hook

    struct nfqnl_msg_packet_hw:
        uint16_t    hw_addrlen
        uint16_t    _pad
        uint8_t     hw_addr[8]

    struct nfqnl_msg_packet_timestamp:
        uint64_t    sec                      #__aligned_be64
        uint64_t    usec                     #__aligned_be64

    enum nfqnl_vlan_attr:
        NFQA_VLAN_UNSPEC,
        NFQA_VLAN_PROTO,                # __be16 skb vlan_proto */
        NFQA_VLAN_TCI,                  # __be16 skb htons(vlan_tci) */
        __NFQA_VLAN_MAX,

        NFQA_VLAN_MAX = __NFQA_VLAN_MAX - 1

    # name causes cython compile error due to integer/enum type mismatch
    enum: # nfqnl_attr_type
        NFQA_UNSPEC,
        NFQA_PACKET_HDR,
        NFQA_VERDICT_HDR,               # nfqnl_msg_verdict_hrd */
        NFQA_MARK,                      # __u32 nfmark */
        NFQA_TIMESTAMP,                 # nfqnl_msg_packet_timestamp */
        NFQA_IFINDEX_INDEV,             # __u32 ifindex */
        NFQA_IFINDEX_OUTDEV,            # __u32 ifindex */
        NFQA_IFINDEX_PHYSINDEV,         # __u32 ifindex */
        NFQA_IFINDEX_PHYSOUTDEV,        # __u32 ifindex */
        NFQA_HWADDR,                    # nfqnl_msg_packet_hw */
        NFQA_PAYLOAD,                   # opaque data payload */
        NFQA_CT,                        # nfnetlink_conntrack.h */
        NFQA_CT_INFO,                   # enum ip_conntrack_info */
        NFQA_CAP_LEN,                   # __u32 length of captured packet */
        NFQA_SKB_INFO,                  # __u32 skb meta information */
        NFQA_EXP,                       # nfnetlink_conntrack.h */
        NFQA_UID,                       # __u32 sk uid */
        NFQA_GID,                       # __u32 sk gid */
        NFQA_SECCTX,                    # security context string */
        NFQA_VLAN,                      # nested attribute: packet vlan info */
        NFQA_L2HDR,                     # full L2 header */
        NFQA_PRIORITY,                  # skb->priority */

        NFQA_MAX

    struct nfqnl_msg_verdict_hdr:
        uint32_t    verdict
        uint32_t    id

    enum NfqnlMsgConfigCmds "nfqnl_msg_config_cmds":
        NFQNL_CFG_CMD_NONE
        NFQNL_CFG_CMD_BIND
        NFQNL_CFG_CMD_UNBIND
        NFQNL_CFG_CMD_PF_BIND
        NFQNL_CFG_CMD_PF_UNBIND

    struct NfqnlMsgConfigCmd "nfqnl_msg_config_cmd":
        uint8_t     command             # nfqnl_msg_config_cmds
        uint8_t     _pad
        uint16_t    pf                  # AF_xxx for PF_[UN]BIND

    enum NfqnlConfigMode "nfqnl_config_mode":
        NFQNL_COPY_NONE
        NFQNL_COPY_META
        NFQNL_COPY_PACKET

    struct NfqnlMsgConfigParams "nfqnl_msg_config_params":
        uint32_t    copy_range
        uint8_t     copy_mode           # enum nfqnl_config_mode
    # __attribute__ ((packed));

    enum NfqnlAttrConfig "nfqnl_attr_config":
        NFQA_CFG_UNSPEC
        NFQA_CFG_CMD                    # nfqnl_msg_config_cmd
        NFQA_CFG_PARAMS                 # nfqnl_msg_config_params
        NFQA_CFG_QUEUE_MAXLEN           # __u32
        NFQA_CFG_MASK                   # identify which flags to change
        NFQA_CFG_FLAGS                  # value of these flags (__u32)
        NFQA_CFG_MAX

    # Flags for NFQA_CFG_FLAGS
    enum:
        NFQA_CFG_F_FAIL_OPEN
        NFQA_CFG_F_CONNTRACK
        NFQA_CFG_F_GSO
        NFQA_CFG_F_UID_GID
        NFQA_CFG_F_MAX

    # flags for NFQA_SKB_INFO
    enum:
        # packet appears to have wrong checksums, but they are ok
        NFQA_SKB_CSUMNOTREADY

        # packet is GSO (i.e., exceeds device mtu)
        NFQA_SKB_GSO

        # csum not validated (incoming device doesn't support hw checksum, etc.)
        NFQA_SKB_CSUM_NOTVERIFIED
