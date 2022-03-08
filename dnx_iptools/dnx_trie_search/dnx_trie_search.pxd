#!/usr/bin/env Cython

from libc.stdint cimport int_fast8_t, int_fast16_t, int_fast32_t, uint_fast8_t, uint_fast16_t, uint_fast32_t

# making generic u/int types aliasing u/int fast
ctypedef int_fast8_t    int8_t
ctypedef int_fast16_t   int16_t
ctypedef int_fast32_t   int32_t
ctypedef uint_fast8_t   u_int8_t
ctypedef uint_fast16_t  u_int16_t
ctypedef uint_fast32_t  u_int32_t

# need signed int because id can be negative with some methods of keying containers
cdef struct L1Recurve:
    int32_t     id
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
    u_int32_t   netid
    u_int32_t   bcast
    u_int8_t    country

cdef class HashTrie:
    cdef:
        TrieMap *TRIE_MAP

        size_t INDEX_MASK

    cpdef void generate_structure(self, tuple py_trie, size_t py_trie_len)
    cdef u_int8_t search(self, u_int32_t trie_key, u_int32_t host_id) nogil
    cdef TrieRange* _make_l2(self, u_int32_t trie_key, (u_int32_t, u_int32_t, u_int16_t) l2_entry)

cdef class RecurveTrie:
    cdef:
        size_t L1_SIZE
        L1Recurve *L1_CONTAINER

    cpdef void generate_structure(self, tuple py_trie)
    cdef long _l1_search(self, long container_id, long host_id) nogil
    cdef u_int16_t _l2_search(self, long container_id, short l2_size, L2Recurve *L2_CONTAINER) nogil
    cdef L2Recurve* _make_l2(self, (long, long) l2_entry)

cdef class RangeTrie:
    cdef:
        size_t L1_SIZE
        L1Range *L1_CONTAINER

    cpdef void generate_structure(self, tuple py_trie)
    cdef long _search(self, long container_id, long host_id) nogil
    cdef L2Range* _make_l2(self, (long, long, short) l2_entry)
