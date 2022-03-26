#!/usr/bin/env Cython

from libc.stdint cimport uint8_t, uint16_t, uint32_t

cdef struct TrieMap_R:
    size_t      len
    TrieRange  *ranges

cdef struct TrieRange:
    uint32_t    key
    uint32_t    netid
    uint32_t    bcast
    uint8_t     country

cdef class HashTrie_Range:
    cdef:
        TrieMap_R  *TRIE_MAP
        uint32_t    max_width

    cdef uint8_t search(self, uint32_t trie_key, uint32_t host_id) nogil
    cdef inline uint32_t hash_key(self, uint32_t trie_key) nogil
    cpdef void generate_structure(self, list py_trie, Py_ssize_t py_trie_len)


cdef struct TrieMap_V:
    size_t      len
    TrieValue  *values

cdef struct TrieValue:
    uint32_t    key
    uint32_t    value

cdef class HashTrie_Value:
    cdef:
        TrieMap_V  *TRIE_MAP
        uint32_t    max_width

    cdef uint32_t search(self, uint32_t trie_key) nogil
    cdef inline uint32_t hash_key(self, uint32_t trie_key) nogil
    cpdef void generate_structure(self, list py_trie, Py_ssize_t py_trie_len)
