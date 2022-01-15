#!/usr/bin/env Cython

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

cdef class HashTrie:
    cdef:
        trie_map *TRIE_MAP

        size_t MAX_KEYS
        size_t INDEX_MASK

cdef class RecurveTrie:
    cdef:
        size_t L1_SIZE
        l1_recurve *L1_CONTAINER

cdef class RangeTrie:
    cdef:
        size_t L1_SIZE
        l1_range *L1_CONTAINER
