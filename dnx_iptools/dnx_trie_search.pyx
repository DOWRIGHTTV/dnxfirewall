#!/usr/bin/env python3

from libc.stdlib cimport malloc, calloc, free

import threading as _threading

from functools import lru_cache as _lru_cache

cdef class TrieRecurvSearch:

    # L1 CONTAINER = [<CONTAINER_ID | L2_CONTAINER_PTR>]

    # L2 CONTAINER = [<CONTAINER_ID | HOST_CATEGORY>]

    def generate_trie_structure(self, tuple signatures):

        # will be accessed from other methods
        self.L1_SIZE = len(signatures)
        self.L1_CONTAINER = <l1_content*>malloc(sizeof(l1_content) * self.L1_SIZE)

        for i in range(self.L1_SIZE):

            # accessed via pointer stored in L1 container
            L2_SIZE = len(signatures[i][1])
            L2_CONTAINER = <l2_content*>malloc(sizeof(l2_content) * L2_SIZE)

            for xi in range(L2_SIZE):

                L2_CONTAINER[xi].id = <u_int32_t>signatures[i][1][xi][0]
                L2_CONTAINER[xi].host_category = <u_int32_t>signatures[i][1][xi][1]

            self.L1_CONTAINER[i].id = < u_int32_t > signatures[i][0]
            self.L1_CONTAINER[i].l2_ptr = L2_CONTAINER[0]

    @_lru_cache(maxsize=4096)
    def trie_search(self, (u_int32_t, u_int32_t) host):

        cdef u_int32_t search_result

        with nogil:
            search_result = self._l1_trie_search(host)

        return search_result

    cdef u_int32_t _l1_trie_search(self, (u_int32_t, u_int32_t) container_ids) nogil:

        cdef:
            u_int32_t left = 0
            u_int32_t right = self.L1_SIZE

            u_int32_t mid

            l1_content l1_container

        while left <= right:
            mid = left + (right - left) // 2
            l1_container = self.L1_CONTAINER[mid]

            # excluding left half
            if (l1_container.id < container_ids[0]):
                left = mid + 1

            # excluding right half
            elif (l1_container.id > container_ids[0]):
                right = mid - 1

            # on bin match, assign var of dataset then recursively call to check host ids
            else:
                return self._l2_trie_search(container_ids[1], l1_container.l2_ptr)
        else:
            return 0

    cdef u_int32_t _l2_trie_search(self, u_int32_t container_id, l2_content *L2_CONTAINER) nogil:

        cdef:
            u_int32_t left = 0
            u_int32_t right = sizeof(L2_CONTAINER) // sizeof(l2_content)

            u_int32_t mid

            l2_content l2_container

        while left <= right:
            mid = left + (right - left) // 2
            l2_container = L2_CONTAINER[mid]

            # excluding left half
            if (l2_container.id < container_id):
                left = mid + 1

            # excluding right half
            elif (l2_container.id > container_id):
                right = mid - 1

            # on bin match, assign var of dataset then recursively call to check host ids
            else:
                return l2_container.host_category
        else:
            return 0

def generate_recursive_binary_search(tuple signatures, (int, int) bounds):

    cdef tuple sigs = signatures
    cdef tuple bin_match = (0,0)

    cdef object recursion_lock = _threading.Lock()

    @_lru_cache(maxsize=8192)
    def recursive_binary_search((long, long) host, bint recursion=0):

        nonlocal bin_match

        cdef long b_id, hb_id, hh_id
        hb_id, hh_id = host

        cdef int left, mid, right

        cdef tuple h_ranges
        cdef long host_match
        cdef short null = 0

        if (not recursion):
            left, right = bounds

            while left <= right:
                mid = left + (right - left) // 2
                b_id, h_ranges = sigs[mid]

                # excluding left half
                if (b_id < hb_id):
                    left = mid + 1

                # excluding right half
                elif (b_id > hb_id):
                    right = mid - 1

                # on bin match, assign var of dataset then recursively call to check host ids
                else:
                    with recursion_lock:
                        bin_match = h_ranges

                        return recursive_binary_search((hh_id, 0), recursion=1)
            else:
                return null

        else:
            # assigning bounds of the items in the bin found in the first search
            left, right = null, len(bin_match)-1

            while left <= right:
                mid = left + (right - left) // 2
                b_id, host_match = bin_match[mid]

                # excluding left half
                if (b_id < hb_id):
                    left = mid + 1

                # excluding right half
                elif (b_id > hb_id):
                    right = mid - 1

                # on bin match, recursively call to check host ids
                else:
                    return host_match

            else:
                return null

    return recursive_binary_search

def generate_linear_binary_search(tuple sigs, (int, int) bounds):

    @_lru_cache(maxsize=4096)
    def linear_binary_search((long, long) host):

        cdef long b_id, hb_id, h_id
        hb_id, h_id = host

        cdef int left, right, mid
        left, right = bounds

        cdef tuple h_ranges

        cdef long r_start, r_end
        cdef short c_code, null = 0
        cdef (long, long, short) h_range

        while left <= right:
            mid = left + (right - left) // 2
            b_id, h_ranges = sigs[mid]

            # excluding left half
            if (b_id < hb_id):
                left = mid + 1

            # excluding right half
            elif (b_id > hb_id):
                right = mid - 1

            # host bin id matches a bin id in sigs
            else:

                #for r_start, r_end, c_code in h_ranges:
                for h_range in h_ranges:
                    r_start, r_end, c_code = h_range
                    if r_start <= h_id <= r_end:
                        return c_code

                else:
                    return null

        else:
            return null

    return linear_binary_search
