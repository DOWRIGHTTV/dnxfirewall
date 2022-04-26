cdef extern from "libmnl/libmnl.h":
    # nlattr mnl_attr_for_each(nlattr attr, nlmsghdr *nlh, int offset)
    # mnl_attr_for_each_nested(nlattr attr, nest)
    # mnl_attr_for_each_payload(payload, size_t payload_size)

    #
    # Netlink socket API
    #
    enum:
        MNL_SOCKET_AUTOPID
        MNL_SOCKET_BUFFER_SIZE

    struct mnl_socket:
        pass

    #define MNL_FRAME_PAYLOAD(frame) ((void *)(frame) + NL_MMAP_HDRLEN)
    # void *MNL_FRAME_PAYLOAD(nl_mmap_hdr *frame)

    mnl_socket *mnl_socket_open(int type)
    mnl_socket *mnl_socket_fdopen(int fd)
    int mnl_socket_bind(mnl_socket *nl, unsigned int groups, pid_t pid)
    int mnl_socket_close(mnl_socket *nl)
    int mnl_socket_get_fd(const mnl_socket *nl)
    unsigned int mnl_socket_get_portid(const mnl_socket *nl)
    ssize_t mnl_socket_sendto(const mnl_socket *nl, const void *req, size_t siz)
    ssize_t mnl_socket_recvfrom(const mnl_socket *nl, void *buf, size_t siz)
    int mnl_socket_setsockopt(const mnl_socket *nl, int type, void *buf, socklen_t len)
    int mnl_socket_getsockopt(const mnl_socket *nl, int type, void *buf, socklen_t *len)

    #
    # Netlink message API
    #
        #define MNL_ALIGN(len)              (((len)+MNL_ALIGNTO-1) & ~(MNL_ALIGNTO-1))
    #define MNL_NLMSG_HDRLEN    MNL_ALIGN(sizeof(struct nlmsghdr))
    int MNL_ALIGN(int len)
    unsigned long int MNL_NLMSG_HDRLEN

    size_t mnl_nlmsg_size(size_t len)
    size_t mnl_nlmsg_get_payload_len(const nlmsghdr *nlh)

    # Netlink message header builder
    nlmsghdr *mnl_nlmsg_put_header(void *buf)
    void *mnl_nlmsg_put_extra_header(nlmsghdr *nlh, size_t size)

    # Netlink message iterators
    bint mnl_nlmsg_ok(const nlmsghdr *nlh, int len)
    nlmsghdr *mnl_nlmsg_next(const nlmsghdr *nlh, int *len)

    # Netlink sequence tracking
    bint mnl_nlmsg_seq_ok(const nlmsghdr *nlh, unsigned int seq)

    # Netlink portID checking
    bint mnl_nlmsg_portid_ok(const nlmsghdr *nlh, unsigned int portid)

    # Netlink message getters
    void *mnl_nlmsg_get_payload(const nlmsghdr *nlh)
    void *mnl_nlmsg_get_payload_offset(const nlmsghdr *nlh, size_t offset)
    void *mnl_nlmsg_get_payload_tail(const nlmsghdr *nlh)

    # Netlink message printer
    void mnl_nlmsg_fprintf(FILE *fd, const void *data, size_t datalen, size_t extra_header_size)

    #
    # Netlink attributes API
    #
    enum:
        MNL_ATTR_HDRLEN

    # TLV attribute getters */
    uint16_t mnl_attr_get_type(const nlattr *attr)
    uint16_t mnl_attr_get_len(const nlattr *attr)
    uint16_t mnl_attr_get_payload_len(const nlattr *attr)
    nfqnl_msg_packet_hdr *mnl_attr_get_payload(const nlattr *attr)
    uint8_t mnl_attr_get_u8(const nlattr *attr)
    uint16_t mnl_attr_get_u16(const nlattr *attr)
    uint32_t mnl_attr_get_u32(const nlattr *attr)
    uint64_t mnl_attr_get_u64(const nlattr *attr)
    const char *mnl_attr_get_str(const nlattr *attr)

    # TLV attribute putters */
    void mnl_attr_put(nlmsghdr *nlh, uint16_t type, size_t len, const void *data)
    void mnl_attr_put_u8(nlmsghdr *nlh, uint16_t type, uint8_t data)
    void mnl_attr_put_u16(nlmsghdr *nlh, uint16_t type, uint16_t data)
    void mnl_attr_put_u32(nlmsghdr *nlh, uint16_t type, uint32_t data)
    void mnl_attr_put_u64(nlmsghdr *nlh, uint16_t type, uint64_t data)
    void mnl_attr_put_str(nlmsghdr *nlh, uint16_t type, const char *data)
    void mnl_attr_put_strz(nlmsghdr *nlh, uint16_t type, const char *data)

    # TLV attribute putters with buffer boundary checkings */
    bint mnl_attr_put_check(nlmsghdr *nlh, size_t buflen, uint16_t type, size_t len, const void *data)
    bint mnl_attr_put_u8_check(nlmsghdr *nlh, size_t buflen, uint16_t type, uint8_t data)
    bint mnl_attr_put_u16_check(nlmsghdr *nlh, size_t buflen, uint16_t type, uint16_t data)
    bint mnl_attr_put_u32_check(nlmsghdr *nlh, size_t buflen, uint16_t type, uint32_t data)
    bint mnl_attr_put_u64_check(nlmsghdr *nlh, size_t buflen, uint16_t type, uint64_t data)
    bint mnl_attr_put_str_check(nlmsghdr *nlh, size_t buflen, uint16_t type, const char *data)
    bint mnl_attr_put_strz_check(nlmsghdr *nlh, size_t buflen, uint16_t type, const char *data)

    # TLV attribute nesting */
    nlattr *mnl_attr_nest_start(nlmsghdr *nlh, uint16_t type)
    nlattr *mnl_attr_nest_start_check(nlmsghdr *nlh, size_t buflen, uint16_t type)
    void mnl_attr_nest_end(nlmsghdr *nlh, nlattr *start)
    void mnl_attr_nest_cancel(nlmsghdr *nlh, nlattr *start)

    # TLV validation */
    int mnl_attr_type_valid(const nlattr *attr, uint16_t maxtype)

    enum mnl_attr_data_type:
        MNL_TYPE_UNSPEC
        MNL_TYPE_U8
        MNL_TYPE_U16
        MNL_TYPE_U32
        MNL_TYPE_U64
        MNL_TYPE_STRING
        MNL_TYPE_FLAG
        MNL_TYPE_MSECS
        MNL_TYPE_NESTED
        MNL_TYPE_NESTED_COMPAT
        MNL_TYPE_NUL_STRING
        MNL_TYPE_BINARY
        MNL_TYPE_MAX

    int mnl_attr_validate(const nlattr *attr, mnl_attr_data_type type)
    int mnl_attr_validate2(const nlattr *attr, mnl_attr_data_type type, size_t len)

    # TLV iterators
    bint mnl_attr_ok(const nlattr *attr, int len)
    nlattr *mnl_attr_next(const nlattr *attr)

    # TLV callback-based attribute parsers
    ctypedef int (*mnl_attr_cb_t)(const nlattr *attr, void *data)
    # struct mnl_attr_cb_t:
    #     pass

    int mnl_attr_parse(const nlmsghdr *nlh, unsigned int offset, mnl_attr_cb_t cb, void *data)
    int mnl_attr_parse_nested(const nlattr *attr, mnl_attr_cb_t cb, void *data)
    int mnl_attr_parse_payload(const void *payload, size_t payload_len, mnl_attr_cb_t cb, void *data)

    #
    # callback API
    #
    enum:
        MNL_CB_ERROR
        MNL_CB_STOP
        MNL_CB_OK

    ctypedef int (*mnl_cb_t)(const nlmsghdr *nlh, void *data)
    # struct mnl_cb_t:
    #     pass

    int mnl_cb_run(const void *buf, size_t numbytes, unsigned int seq,
                            unsigned int portid, mnl_cb_t cb_data, void *data)

    int mnl_cb_run2(const void *buf, size_t numbytes, unsigned int seq,
                            unsigned int portid, mnl_cb_t cb_data, void *data,
                            const mnl_cb_t *cb_ctl_array, unsigned int cb_ctl_array_len)
