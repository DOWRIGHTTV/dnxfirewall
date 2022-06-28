cdef extern from "linux/netlink.h" nogil:
    enum:
        NETLINK_ROUTE                 # Routing/device hook           # Unused number
        NETLINK_USERSOCK              # Reserved for user mode socket protocols
        NETLINK_FIREWALL              # Unused number, formerly ip_queue
        NETLINK_SOCK_DIAG             # socket monitoring
        NETLINK_NFLOG                 # netfilter/iptables ULOG                 # ipsec
        NETLINK_SELINUX               # SELinux event notifications
        NETLINK_CONNECTOR
        NETLINK_NETFILTER             # netfilter subsystem

    struct nlmsghdr:
        uint32_t nlmsg_len              # Length of message including header
        uint16_t nlmsg_type             # Message content
        uint16_t nlmsg_flags            # Additional flags
        uint32_t nlmsg_seq              # Sequence number
        uint32_t nlmsg_pid              # Sending process port ID

    #define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
    int NLMSG_ALIGN(int len)

    #define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
    int NLMSG_LENGTH(int len)

    #define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
    int NLMSG_SPACE(int len)

    #define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
    void *NLMSG_DATA(nlmsghdr *nlh)

    # define NLMSG_NEXT(nlh,len) below as inline cdef

    #define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
    #                      (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
    #                      (nlh)->nlmsg_len <= (len))
    bint NLMSG_OK(nlmsghdr *nlh, len)

    #define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))
    int NLMSG_PAYLOAD(nlmsghdr *nlh, len)

    struct nlmsgerr:
        int             error
        nlmsghdr        msg

    enum: NETLINK_NO_ENOBUFS

    enum:
        NETLINK_UNCONNECTED
        NETLINK_CONNECTED

    #  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
    # +---------------------+- - -+- - - - - - - - - -+- - -+
    # |        Header       | Pad |     Payload       | Pad |
    # |   (struct nlattr)   | ing |                   | ing |
    # +---------------------+- - -+- - - - - - - - - -+- - -+
    #  <-------------- nlattr->nla_len -------------->
    struct nlattr:
        uint16_t nla_len
        uint16_t nla_type

    # nla_type (16 bits)
    # +---+---+-------------------------------+
    # | N | O | Attribute Type                |
    # +---+---+-------------------------------+
    # N := Carries nested attributes
    # O := Payload stored in network byte order
    #
    # Note: The N and O flag are mutually exclusive.
    enum:
        NLA_F_NESTED
        NLA_F_NET_BYTEORDER
        NLA_TYPE_MASK
        NLA_ALIGNTO

    #define NLA_ALIGN(len)              (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
    int NLA_ALIGN(int len)

    enum: NLA_HDRLEN

#define NLMSG_NEXT(nlh,len)      ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
#                                 (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
cdef inline nlmsghdr *NLMSG_NEXT(nlmsghdr *nlh, int *len) nogil:
    len[0] -= NLMSG_ALIGN(nlh.nlmsg_len)
    return <nlmsghdr*>(<char*>nlh + NLMSG_ALIGN(nlh.nlmsg_len))