#!/usr/bin/env Cython

# cython: cdivision=True

from libc.stdlib cimport malloc, calloc, realloc
from libc.stdint cimport uint8_t, uint16_t, uint32_t

DEF EMPTY_CONTAINER = 0
DEF NO_MATCH = 0

DEF MAX_WIDTH_MULTIPLIER = 2

# ================================================
# C STRUCTURES - converted from python tuples
# ================================================
cdef class HashTrie_Range:

    def py_search(s, tuple host):
        cdef:
            uint8_t search_result

            uint32_t trie_key = <uint32_t>host[0]
            uint32_t host_id  = <uint32_t>host[1]

        with nogil:
            search_result = s.search(trie_key, host_id)

        return search_result

    cdef uint8_t search(s, uint32_t trie_key, uint32_t host_id) nogil:

        cdef:
            size_t      i

            TrieMap_R  *trie_value = &s.TRIE_MAP[s.hash_key(trie_key)]

        # no l1 match
        if (trie_value.len == EMPTY_CONTAINER):
            return NO_MATCH

        for i in range(trie_value.len):

            # this is needed because collisions are possible by design.
            # matching the original key will guarantee the correct range is being evaluated.
            if (trie_value.ranges[i].key != trie_key):
                continue

            if (trie_value.ranges[i].netid <= host_id <= trie_value.ranges[i].bcast):
                return trie_value.ranges[i].country

        # iteration completed with no l2 match
        return NO_MATCH

    cdef inline uint32_t hash_key(s, uint32_t trie_key) nogil:
        return trie_key % (s.max_width - 1)

    cpdef void generate_structure(s, list py_trie, Py_ssize_t py_trie_len):

        cdef:
            size_t      i, xi

            TrieMap_R  *trie_map_container
            TrieRange  *trie_multival

            uint32_t    trie_key
            uint32_t    trie_key_hash
            list        trie_vals
            size_t      num_values

        # TODO: test the multiplier for max_width (current is 2, try 1.3)
        s.max_width = <uint32_t>py_trie_len * MAX_WIDTH_MULTIPLIER
        s.TRIE_MAP  = <TrieMap_R*>calloc(s.max_width, sizeof(TrieMap_R))

        for i in range(py_trie_len):

            trie_key   = <uint32_t>py_trie[i][0]
            trie_vals  = py_trie[i][1]
            num_values = <size_t>len(trie_vals)

            trie_key_hash = s.hash_key(trie_key)
            trie_map_container = &s.TRIE_MAP[trie_key_hash]

            # first time on index so allocating memory for the number of current multi-vals this iteration
            if (trie_map_container.len == 0):
                trie_map_container.ranges = <TrieRange*>malloc(sizeof(TrieRange) * num_values)

            # at least 1 multi-val is present, so reallocating memory to include new multi-vals
            else:
                trie_map_container.ranges = <TrieRange*>realloc(
                    trie_map_container.ranges, sizeof(TrieRange) * (trie_map_container.len + num_values)
                )

            # define struct members for each range in py_l2
            for xi in range(num_values):
                trie_multival = &trie_map_container.ranges[trie_map_container.len + xi]

                trie_multival.key     = trie_key
                trie_multival.netid   = <uint32_t>py_trie[i][1][xi][0]
                trie_multival.bcast   = <uint32_t>py_trie[i][1][xi][1]
                trie_multival.country = <uint16_t>py_trie[i][1][xi][2]

            trie_map_container.len += num_values

cdef class HashTrie_Value:

    def py_search(s, uint32_t trie_key):
        cdef:
            uint32_t search_result

        with nogil:
            search_result = s.search(trie_key)

        return search_result

    cdef uint32_t search(s, uint32_t trie_key) nogil:

        cdef:
            size_t      i

            TrieMap_V  *trie_container = &s.TRIE_MAP[s.hash_key(trie_key)]

        # no l1 match
        if (trie_container.len == EMPTY_CONTAINER):
            return NO_MATCH

        for i in range(trie_container.len):

            # this is needed because collisions are possible by design.
            # matching the original key will guarantee the correct value is returned.
            if (trie_container.values[i].key == trie_key):

                return trie_container.values[i].value

        # iteration completed with no l2 match
        return NO_MATCH

    cdef inline uint32_t hash_key(s, uint32_t trie_key) nogil:
        return trie_key % (s.max_width - 1)

    cpdef void generate_structure(s, list py_trie, Py_ssize_t py_trie_len):

        cdef:
            size_t      i

            TrieMap_V  *trie_map_container
            TrieValue  *trie_multival

            uint32_t    trie_key
            uint32_t    trie_key_hash
            uint32_t    trie_val

        # max_width will be ~130% of the size of py_trie
        s.max_width = <uint32_t>py_trie_len + (py_trie_len // 3)
        s.TRIE_MAP  = <TrieMap_V*>calloc(s.max_width, sizeof(TrieMap_V))

        for i in range(py_trie_len):

            trie_key = <uint32_t>py_trie[i][0]
            trie_val = <uint32_t>py_trie[i][1]

            trie_key_hash = s.hash_key(trie_key)
            trie_map_container = &s.TRIE_MAP[trie_key_hash]

            # first time on index so allocating memory for the number of current multi-vals this iteration
            if (trie_map_container.len == 0):
                trie_map_container.values = <TrieValue*>malloc(sizeof(TrieValue))

            # at least 1 multi-val is present, so reallocating memory to include new multi-vals
            else:
                trie_map_container.values = <TrieValue*>realloc(
                    trie_map_container.values, sizeof(TrieValue) * (trie_map_container.len + 1)
                )

            trie_multival = &trie_map_container.values[trie_map_container.len]

            trie_multival.key   = trie_key
            trie_multival.value = trie_val

            trie_map_container.len += 1
