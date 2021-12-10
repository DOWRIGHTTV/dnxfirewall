#!/usr/bin/env python3

cdef extern from "sys/types.h":
    ctypedef unsigned char u_int8_t
    ctypedef unsigned short int u_int16_t
    ctypedef unsigned int u_int32_t

cdef struct l1_recurve:
    long id
    short l2_size
    l2_recurve *l2_ptr

cdef struct l2_recurve:
    long id
    short host_category

cdef struct l1_range:
    long id
    short l2_size
    l2_range *l2_ptr

cdef struct l2_range:
    long network_id
    long broadcast_id
    short country_code

cdef struct trie_map:
    u_int16_t len
    trie_range *ranges

cdef struct trie_range:
    u_int32_t key
    u_int32_t net_id
    u_int32_t bcast
    u_int8_t country

cdef class RecurveTrie:

    cdef:

        l1_recurve *L1_CONTAINER
        l2_recurve *L2_CONTAINER

        size_t L1_SIZE
        size_t L2_SIZE

    cdef l2_recurve* _make_l2(self, (long, long) l2_entry)
    cdef long _l1_search(self, long container_id, long host_id) nogil
    cdef long _l2_search(self, long container_id, short l2_size, l2_recurve **L2_CONTAINER) nogil
    cpdef void generate_structure(self, tuple py_trie)

cdef class RangeTrie:

    cdef:

        l1_range *L1_CONTAINER
        l2_range *L2_CONTAINER

        size_t L1_SIZE
        size_t L2_SIZE

    cdef l2_range* _make_l2(self, (long, long, short) l2_entry)
    cdef long _search(self, long container_id, long host_id) nogil
    cpdef void generate_structure(self, tuple py_trie)

cdef class HashTrie:

    cdef:

        trie_map *TRIE_MAP
        trie_range *TRIE_VALUE_RANGES

        u_int32_t MAX_KEYS
        u_int32_t INDEX_MASK
        size_t VALUE_LEN

        u_int32_t TRIE_KEY
        u_int32_t TRIE_KEY_HASH

    cdef trie_range* _make_l2(self, u_int32_t trie_key, (u_int32_t, u_int32_t, u_int16_t) l2_entry)
    cdef u_int8_t _search(self, u_int32_t container_id, u_int32_t host_id)
    cpdef void generate_structure(self, tuple py_trie)
