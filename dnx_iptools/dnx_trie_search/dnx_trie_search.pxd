#!/usr/bin/env Cython

from libc.stdint cimport uint8_t, uint16_t, uint32_t

cdef struct L1Recurve:
    uint32_t    id
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
    TrieRange  *ranges[100]

cdef struct TrieRange:
    uint32_t    key
    uint32_t    netid
    uint32_t    bcast
    uint8_t     country

cdef class HashTrie:
    cdef:
        TrieMap    *TRIE_MAP
        uint32_t    max_width

    cdef uint8_t search(self, uint32_t trie_key, uint32_t host_id)
    cdef inline uint32_t hash_key(self, uint32_t trie_key)
    cpdef void generate_structure(self, list py_trie, Py_ssize_t py_trie_len)

cdef class RecurveTrie:
    cdef:
        size_t      L1_SIZE
        L1Recurve  *L1_CONTAINER

    cpdef void generate_structure(self, list py_trie)
    cdef uint16_t l1_search(self, uint32_t container_id, uint32_t host_id) nogil
    cdef uint16_t l2_search(self, uint32_t container_id, L1Recurve *l1_container) nogil

cdef class RangeTrie:
    cdef:
        size_t      L1_SIZE
        L1Range    *L1_CONTAINER

    cpdef void generate_structure(self, list py_trie)
    cdef uint16_t l1_search(self, uint32_t container_id, uint32_t host_id) nogil
