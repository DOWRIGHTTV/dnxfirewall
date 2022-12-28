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

# HTR_List > HTR_L1 > HTR_L2
cdef struct HTR_L1:
    size_t      len
    HTR_L2     *multi_val

cdef struct HTR_L2:
    uint32_t    key
    uint32_t    netid
    uint32_t    bcast
    uint8_t     country

cdef struct HTR_Slot:
    size_t      len
    HTR_L1     *keys

cdef public uint8_t htr_search(int trie_idx, uint32_t trie_key, uint32_t host_id) nogil
cdef int htr_generate_structure(list py_trie, size_t py_trie_len)
# cdef public class HashTrie_Range [object HashTrie_Range, type HashTrie_Range_T]
#
# ctypedef public uint8_t (*htr_search_t)(HashTrie_Range, uint32_t, uint32_t)

cdef class HashTrie_Range:  # [object HashTrie_Range, type HashTrie_Range_T]:
    cdef:
        TrieMap_R      *TRIE_MAP
        uint32_t        max_width
        # htr_search_t    lookup # will be set as search method ptr

    cdef  uint8_t search(s, uint32_t trie_key, uint32_t host_id) nogil
    cdef  uint32_t hash_key(s, uint32_t trie_key) nogil
    cpdef void generate_structure(s, list py_trie, size_t py_trie_len)


cdef struct TrieMap_V:
    size_t      len
    TrieValue  *values

cdef struct TrieValue:
    uint32_t    key
    uint32_t    value


cdef class HashTrie_Value:  # [object HashTrie_Value, type HashTrie_Value_T]:
    cdef:
        TrieMap_V  *TRIE_MAP
        uint32_t    max_width

    cdef  public uint32_t search(s, uint32_t trie_key) nogil
    cdef  uint32_t hash_key(s, uint32_t trie_key) nogil
    cpdef void generate_structure(s, list py_trie, size_t py_trie_len)
