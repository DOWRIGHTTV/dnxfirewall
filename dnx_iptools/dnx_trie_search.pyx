#!/usr/bin/env Cython

from libc.stdlib cimport malloc, calloc
# from libc.stdio cimport printf

import threading as _threading
from math import log as _log

from functools import lru_cache as _lru_cache

DEF EMPTY_CONTAINER = 0
DEF NO_MATCH = 0


# ================================================ #
# C STRUCTURES - converted from python tuples
# ================================================ #
cdef class HashTrie:

    cpdef void generate_structure(self, tuple py_trie):

        cdef:
            size_t value_len

            u_int32_t TRIE_KEY
            u_int32_t TRIE_KEY_HASH

            trie_range *trie_value_ranges

        # allocating memory for L1 container. this will be accessed from l1_search method.
        # the reference stored at index will point to l2 data.
        MAX_KEYS = 2 ** round(_log(len(py_trie), 2))

        self.INDEX_MASK = MAX_KEYS - 1
        self.TRIE_MAP = <trie_map*> calloc(MAX_KEYS, sizeof(trie_map))

        for i in range(len(py_trie)):

            # accessed via pointer stored in L1 container
            value_len = len(py_trie[i][1])

            # assigning l2 container reference to calculated hash index
            TRIE_KEY = <long>py_trie[i][0]
            TRIE_KEY_HASH = TRIE_KEY % self.INDEX_MASK

            # allocating memory for trie_ranges
            trie_value_ranges = <trie_range*>malloc(sizeof(trie_range) * value_len)

            # make function for trie_range struct for each range in py_l2
            for xi in range(value_len):
                trie_value_ranges[xi] = self._make_l2(TRIE_KEY, py_trie[i][1][xi])[0]

            self.TRIE_MAP[TRIE_KEY_HASH].len = value_len
            self.TRIE_MAP[TRIE_KEY_HASH].ranges = trie_value_ranges

    cdef u_int8_t _search(self, u_int32_t trie_key, u_int32_t host_id) nogil:

        cdef:
            size_t trie_key_hash = trie_key % self.INDEX_MASK
            trie_map trie_value  = self.TRIE_MAP[trie_key_hash]

        # no l1 match
        if (trie_value.len == EMPTY_CONTAINER):
            return NO_MATCH

        for i in range(trie_value.len):

            # this is needed because collisions are possible by design so matching the unhashed key will guarantee the
            # correct range is being evaluated.
            if (trie_value.ranges[i].key != trie_key):
                continue

            if (trie_value.ranges[i].netid <= host_id <= trie_value.ranges[i].bcast):
                return trie_value.ranges[i].country

        # iteration completed with no l2 match
        return NO_MATCH

    cdef trie_range* _make_l2(self, u_int32_t trie_key, (u_int32_t, u_int32_t, u_int16_t) l2_entry):
        '''allocates memory for a single L2 content struct, assigns members from l2_entry, then returns pointer.'''

        cdef trie_range *l2_content = <trie_range*>malloc(sizeof(trie_range))

        l2_content.key     = trie_key
        l2_content.netid  = l2_entry[0]
        l2_content.bcast   = l2_entry[1]
        l2_content.country = l2_entry[2]

        return l2_content

cdef class RecurveTrie:
    '''
    L1 CONTAINER = [<CONTAINER_ID, L2_CONTAINER_SIZE, L2_CONTAINER_PTR>]
    L2 CONTAINER = [<CONTAINER_ID, HOST_CATEGORY>]
    '''

    @_lru_cache(maxsize=4096)
    def search(self, (long, long) host):

        cdef long search_result

        with nogil:
            search_result = self._l1_search(host[0], host[1])

        return search_result

    cpdef void generate_structure(self, tuple py_trie):

        cdef:
            size_t L2_SIZE
            l2_recurve *L2_CONTAINER

        # allocating memory for L1 container. this will be accessed from l1_search method.
        # L1 container will be iterated over, being checked for id match. if a match is found
        # the reference stored at that index will be used to check for l2 container id match.
        self.L1_SIZE = len(py_trie)
        self.L1_CONTAINER = <l1_recurve*>malloc(sizeof(l1_recurve) * self.L1_SIZE)

        for i in range(self.L1_SIZE):

            # accessed via pointer stored in L1 container
            L2_SIZE = len(py_trie[i][1])

            # allocating memory for individual L2 containers
            L2_CONTAINER = <l2_recurve*>malloc(sizeof(l2_recurve) * L2_SIZE)

            # calling make function for l2 content struct for each entry in current py_l2 container
            for xi in range(L2_SIZE):
                L2_CONTAINER[xi] = self._make_l2(py_trie[i][1][xi])[0]

            # assigning struct members to current index of L1 container.
            self.L1_CONTAINER[i].id = <u_int32_t>py_trie[i][0]
            self.L1_CONTAINER[i].l2_size = L2_SIZE
            self.L1_CONTAINER[i].l2_ptr  = L2_CONTAINER

    cdef long _l1_search(self, long container_id, long host_id) nogil:

        cdef:
            long left = 0
            long mid
            long right = self.L1_SIZE

            l1_recurve l1_container

        while left <= right:
            mid = left + (right - left) // 2
            l1_container = self.L1_CONTAINER[mid]

            # excluding left half
            if (l1_container.id < container_id):
                left = mid + 1

            # excluding right half
            elif (l1_container.id > container_id):
                right = mid - 1

            # TODO: why are we sending in a ptr to the ptr? should be able to pass first.
            # l1.id match. calling l2_search with ptr to l2_containers looking for l2.id match
            else:
                return self._l2_search(host_id, l1_container.l2_size, l1_container.l2_ptr)

        # L1 default
        return NO_MATCH

    cdef long _l2_search(self, long container_id, short l2_size, l2_recurve *L2_CONTAINER) nogil:

        cdef:
            short left = 0
            short mid
            short right = l2_size

            l2_recurve l2_container

        while left <= right:
            mid = left + (right - left) // 2
            l2_container = L2_CONTAINER[mid]

            # excluding left half
            if (l2_container.id < container_id):
                left = mid + 1

            # excluding right half
            elif (l2_container.id > container_id):
                right = mid - 1

            # l2.id match. returning struct value
            else:
                return l2_container.host_cat

        # L2 default
        return NO_MATCH

    cdef l2_recurve* _make_l2(self, (long, long) l2_entry):
        '''allocates memory for a single L2 content struct, assigns members from l2_entry, then
        returns pointer.'''

        cdef l2_recurve *l2_content = <l2_recurve*>malloc(sizeof(l2_recurve))

        l2_content.id = l2_entry[0]
        l2_content.host_cat = l2_entry[1]

        return l2_content


cdef class RangeTrie:
    '''
    L1 CONTAINER = [<CONTAINER_ID, L2_CONTAINER_SIZE, L2_CONTAINER_PTR>]
    L2 CONTAINER = [<NETWORK_ID, BROADCAST_ID, HOST_COUNTRY>]
    '''

    @_lru_cache(maxsize=4096)
    def search(self, (long, long) host):

        cdef long search_result

        with nogil:
            search_result = self._search(host[0], host[1])

        return search_result

    cpdef void generate_structure(self, tuple py_trie):

        cdef:
            size_t L2_SIZE

        # allocating memory for L1 container. this will be accessed from l1_search method.
        # L1 container will be iterated over, being checked for id match. if a match is found
        # the reference stored at that index will be used to check for l2 container id match.
        self.L1_SIZE = len(py_trie)
        self.L1_CONTAINER = <l1_range*>malloc(sizeof(l1_range) * self.L1_SIZE)

        for i in range(self.L1_SIZE):

            L2_SIZE = len(py_trie[i][1])

            # assigning struct members to current index of L1 container
            self.L1_CONTAINER[i].id = <u_int32_t>py_trie[i][0]
            self.L1_CONTAINER[i].l2_size = L2_SIZE

            # allocating memory for individual L2 containers
            self.L1_CONTAINER[i].l2_ptr = <l2_range*>malloc(sizeof(l2_range) * L2_SIZE)

            # calling make function for l2 content struct for each entry in current py_l2 container
            for xi in range(L2_SIZE):
                self.L1_CONTAINER[i][xi] = self._make_l2(py_trie[i][1][xi])[0]

    # NOTE: this will be called directly from cfirewall until lru_cache is ported with no gil needed
    cdef long _search(self, long container_id, long host_id) nogil:

        cdef:
            long left = 0
            long mid
            long right = self.L1_SIZE

            l1_range l1_container
            l2_range l2_container

        while left <= right:
            mid = left + (right - left) // 2
            l1_container = self.L1_CONTAINER[mid]

            # excluding left half
            if (l1_container.id < container_id):
                left = mid + 1

            # excluding right half
            elif (l1_container.id > container_id):
                right = mid - 1

            # l1.id match. iterating over l2_containers looking for l2.id match
            else:
                for i in range(l1_container.l2_size):

                    l2_container = l1_container.l2_ptr[i]

                    if (l2_container.netid <= host_id <= l2_container.bcast):
                        return l2_container.country

                # l2 default > can probably remove and use l1 default below
                return NO_MATCH

        # l1 match
        return NO_MATCH

    cdef l2_range* _make_l2(self, (long, long, short) l2_entry):
        '''allocates memory for a single L2 content struct, assigns members from l2_entry, then returns pointer.'''

        cdef l2_range *l2_content = <l2_range*>malloc(sizeof(l2_range))

        l2_content.netid   = l2_entry[0]
        l2_content.bcast   = l2_entry[1]
        l2_content.country = l2_entry[2]

        return l2_content


# ================================================ #
# TYPED PYTHON STRUCTURES - keeping as alternative
# ================================================ #
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
