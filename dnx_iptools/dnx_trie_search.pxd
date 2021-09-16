#!/usr/bin/env python3

cdef extern from "sys/types.h":
    ctypedef unsigned char u_int8_t
    ctypedef unsigned short int u_int16_t
    ctypedef unsigned int u_int32_t

cdef struct l1_content:
    u_int32_t id
    l2_content *l2_ptr

cdef struct l2_content:
    u_int32_t id
    u_int32_t host_category

cdef class TrieRecurvSearch:

    cdef:

        l1_content *L1_CONTAINER
        l2_content *L2_CONTAINER

        size_t L1_SIZE
        size_t L2_SIZE

    cdef u_int32_t _l1_trie_search(self, (u_int32_t, u_int32_t) container_ids) nogil:
    cdef u_int32_t _l2_trie_search(self, u_int32_t container_id, l2_content *L2_CONTAINER) nogil: