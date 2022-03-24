#!/usr/bin/env Cython

from libc.stdint cimport int8_t, int16_t, int32_t, uint8_t, uint16_t, uint32_t

# need signed int because id can be negative with some methods of keying containers
cdef struct L1Recurve:
    int32_t     id
    size_t      l2_size
    L2Recurve  *l2_ptr

cdef struct L2Recurve:
    uint32_t    id
    uint16_t    host_cat

cdef struct L1Range:
    uint32_t    id
    size_t      l2_size
    L2Range    *l2_ptr

cdef struct L2Range:
    uint32_t    netid
    uint32_t    bcast
    uint8_t     country

cdef struct TrieMap:
    size_t      len
    TrieRange  *ranges

cdef struct TrieRange:
    uint32_t    key
    uint32_t    netid
    uint32_t    bcast
    uint8_t     country

cdef class HashTrie:
    cdef:
        TrieMap *TRIE_MAP

        size_t INDEX_MASK

    cpdef void generate_structure(self, tuple py_trie, size_t py_trie_len)
    cdef uint8_t search(self, uint32_t trie_key, uint32_t host_id) nogil
    cdef TrieRange* make_l2(self, uint32_t trie_key, (uint32_t, uint32_t, uint16_t) l2_entry)

cdef class RecurveTrie:
    cdef:
        size_t L1_SIZE
        L1Recurve *L1_CONTAINER

    cpdef void generate_structure(self, tuple py_trie)
    cdef uint16_t l1_search(self, int32_t container_id, uint32_t host_id) nogil
    cdef uint16_t l2_search(self, uint32_t container_id, L1Recurve *l1_container) nogil
    cdef L2Recurve* make_l2(self, (uint32_t, uint16_t) l2_entry)

cdef class RangeTrie:
    cdef:
        size_t L1_SIZE
        L1Range *L1_CONTAINER

    cpdef void generate_structure(self, tuple py_trie)
    cdef uint32_t search(self, uint32_t container_id, uint32_t host_id) nogil
    cdef L2Range* make_l2(self, (long, long, short) l2_entry)
