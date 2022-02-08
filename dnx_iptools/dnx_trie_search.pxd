#!/usr/bin/env Cython

cdef extern from "sys/types.h":
    ctypedef unsigned char      u_int8_t
    ctypedef unsigned short int u_int16_t
    ctypedef unsigned int       u_int32_t

cdef struct L1Recurve:
    u_int32_t   id
    size_t      l2_size
    L2Recurve  *l2_ptr

cdef struct L2Recurve:
    u_int32_t   id
    u_int16_t   host_cat

cdef struct L1Range:
    u_int32_t   id
    size_t      l2_size
    L2Range    *l2_ptr

cdef struct L2Range:
    u_int32_t   netid
    u_int32_t   bcast
    u_int8_t    country

cdef struct TrieMap:
    size_t      len
    TrieRange  *ranges

cdef struct TrieRange:
    u_int32_t   key
    u_int32_t   net_id
    u_int32_t   bcast
    u_int8_t    country

cdef class HashTrie:
    cdef:
        TrieMap *TRIE_MAP

        size_t INDEX_MASK

    cpdef void generate_structure(self, tuple py_trie)
    cdef u_int8_t search(self, u_int32_t trie_key, u_int32_t host_id) nogil
    cdef TrieRange* _make_l2(self, u_int32_t trie_key, (u_int32_t, u_int32_t, u_int16_t) l2_entry)

cdef class RecurveTrie:
    cdef:
        size_t L1_SIZE
        L1Recurve *L1_CONTAINER

    cpdef void generate_structure(self, tuple py_trie)
    cdef long _l1_search(self, long container_id, long host_id) nogil
    cdef long _l2_search(self, long container_id, short l2_size, L2Recurve *L2_CONTAINER) nogil
    cdef L2Recurve* _make_l2(self, (long, long) l2_entry)

cdef class RangeTrie:
    cdef:
        size_t L1_SIZE
        L1Range *L1_CONTAINER

    cpdef void generate_structure(self, tuple py_trie)
    cdef long _search(self, long container_id, long host_id) nogil
    cdef L2Range* _make_l2(self, (long, long, short) l2_entry)
