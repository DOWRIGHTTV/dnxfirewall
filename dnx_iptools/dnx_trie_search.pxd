#!/usr/bin/env Cython

cdef extern from "sys/types.h":
    ctypedef unsigned char      u_int8_t
    ctypedef unsigned short int u_int16_t
    ctypedef unsigned int       u_int32_t

cdef struct l1_recurve:
    u_int32_t   id
    size_t      l2_size
    l2_recurve  *l2_ptr

cdef struct l2_recurve:
    u_int32_t   id
    u_int16_t   host_cat

cdef struct l1_range:
    u_int32_t   id
    size_t      l2_size
    l2_range    *l2_ptr

cdef struct l2_range:
    u_int32_t   netid
    u_int32_t   bcast
    u_int8_t    country

cdef struct trie_map:
    size_t      len
    trie_range  *ranges

cdef struct trie_range:
    u_int32_t   key
    u_int32_t   net_id
    u_int32_t   bcast
    u_int8_t    country

cdef class HashTrie:
    cdef:
        trie_map *TRIE_MAP

        size_t MAX_KEYS
        size_t INDEX_MASK

    cpdef void generate_structure(self, tuple py_trie)
    cdef u_int8_t _search(self, u_int32_t trie_key, u_int32_t host_id) nogil
    cdef trie_range* _make_l2(self, u_int32_t trie_key, (u_int32_t, u_int32_t, u_int16_t) l2_entry)

cdef class RecurveTrie:
    cdef:
        size_t L1_SIZE
        l1_recurve *L1_CONTAINER

    cpdef void generate_structure(self, tuple py_trie)
    cdef long _l1_search(self, long container_id, long host_id) nogil
    cdef long _l2_search(self, long container_id, short l2_size, l2_recurve *L2_CONTAINER) nogil
    cdef l2_recurve* _make_l2(self, (long, long) l2_entry)

cdef class RangeTrie:
    cdef:
        size_t L1_SIZE
        l1_range *L1_CONTAINER

    cpdef void generate_structure(self, tuple py_trie)
    cdef long _search(self, long container_id, long host_id) nogil
    cdef l2_range* _make_l2(self, (long, long, short) l2_entry)
