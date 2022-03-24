#!/usr/bin/env Cython

# ===============
# PYTHON IMPORTS
# ===============
import threading as _threading

from functools import lru_cache as _lru_cache

# ===============
# C IMPORTS
# ===============
from libc.stdlib cimport malloc, calloc
from libc.math cimport log2
from libc.stdint cimport int8_t, int16_t, int32_t, uint8_t, uint16_t, uint32_t

DEF EMPTY_CONTAINER = 0
DEF NO_MATCH = 0

cdef uint32_t UINT32_MAX = 4294967295

# ================================================
# C STRUCTURES - converted from python tuples
# ================================================
cdef class HashTrie:

    @_lru_cache(maxsize=4096)
    def py_search(self, (long, long) host):
        '''used for testing functions of data structure and searching.
        '''
        cdef uint8_t search_result

        with nogil:
            search_result = self.search(host[0], host[1])

        return search_result

    cpdef void generate_structure(self, list py_trie, size_t py_trie_len):

        cdef:
            size_t trie_key
            size_t trie_key_hash
            size_t value_len

            TrieRange *trie_value_ranges

            size_t max_width = <size_t>2 ** log2(py_trie_len)

        self.INDEX_MASK = <size_t>(max_width - 1)

        self.TRIE_MAP = <TrieMap*>calloc(max_width, sizeof(TrieMap))

        for i in range(py_trie_len):

            trie_key = <size_t>py_trie[i][0]
            trie_key_hash = trie_key % self.INDEX_MASK

            value_len = <size_t>len(py_trie[i][1])

            # allocating memory for trie_ranges
            trie_values = <TrieRange*>malloc(sizeof(TrieRange) * value_len)

            # make function for trie_range struct for each range in py_l2
            for xi in range(value_len):
                trie_values[xi] = self.make_l2(trie_key, py_trie[i][1][xi])[0]

            # assigning struct members
            self.TRIE_MAP[trie_key_hash].len    = value_len
            self.TRIE_MAP[trie_key_hash].ranges = trie_values

    cdef uint8_t search(self, uint32_t trie_key, uint32_t host_id) nogil:

        cdef:
            TrieMap *trie_value = &self.TRIE_MAP[trie_key % self.INDEX_MASK]

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

    cdef TrieRange* make_l2(self, uint32_t trie_key, list l2_entry):
        '''allocates memory for a single L2 content struct, assigns members from l2_entry, then returns pointer.
        '''
        cdef TrieRange *l2_content = <TrieRange*>malloc(sizeof(TrieRange))

        l2_content.key     = trie_key
        l2_content.netid   = <uint32_t>l2_entry[0]
        l2_content.bcast   = <uint32_t>l2_entry[1]
        l2_content.country = <uint16_t>l2_entry[2]

        return l2_content

cdef class RecurveTrie:
    '''
    L1 CONTAINER = [<CONTAINER_ID, L2_CONTAINER_SIZE, L2_CONTAINER_PTR>]
    L2 CONTAINER = [<CONTAINER_ID, HOST_CATEGORY>]
    '''
    @_lru_cache(maxsize=4096)
    def search(self, (long, long) host):

        cdef uint16_t search_result

        with nogil:
            search_result = self.l1_search(host[0], host[1])

        return search_result

    cpdef void generate_structure(self, list py_trie):

        cdef:
            uint32_t    l1_id
            size_t      l2_size
            L2Recurve  *l2_container

        # allocating memory for L1 container
        self.L1_SIZE = <size_t>len(py_trie)
        self.L1_CONTAINER = <L1Recurve*>malloc(sizeof(L1Recurve) * self.L1_SIZE)

        for i in range(self.L1_SIZE):

            l1_id   = <uint32_t>py_trie[i][0]
            l2_size = <size_t>len(py_trie[i][1])

            # allocating memory for an array of l2 container pointers
            l2_container = <L2Recurve*>malloc(sizeof(L2Recurve) * l2_size)

            # calling make function for l2 content struct for each entry in the current py_l2 container
            for xi in range(l2_size):
                l2_container[xi] = self.make_l2(py_trie[i][1][xi])[0]

            # assigning struct members to the current index of L1 container.
            self.L1_CONTAINER[i].id = l1_id
            self.L1_CONTAINER[i].l2_size = l2_size
            self.L1_CONTAINER[i].l2_ptr  = l2_container

    cdef uint16_t l1_search(self, uint32_t l1_id, uint32_t l2_id) nogil:

        cdef:
            size_t mid

            size_t left_bound = 0
            size_t right_bound = self.L1_SIZE

            L1Recurve *l1_container

        while left_bound <= right_bound:
            mid = left_bound + (right_bound - left_bound) // 2
            l1_container = &self.L1_CONTAINER[mid]

            # excluding left half
            if (l1_container.id < l1_id):
                left_bound = mid + 1

            # excluding right half
            elif (l1_container.id > l1_id):
                right_bound = mid - 1

            # l1.id match. calling l2_search with ptr to l2_containers looking for l2.id match
            else:
                return self.l2_search(l2_id, l1_container)

        # L1 default
        return NO_MATCH

    cdef uint16_t l2_search(self, uint32_t l2_id, L1Recurve *l1_container) nogil:

        cdef:
            size_t mid
            L2Recurve *l2_container

            size_t left_bound = 0
            size_t right_bound = l1_container.l2_size

            L2Recurve *L2_CONTAINER = l1_container.l2_ptr

        while left_bound <= right_bound:
            mid = left_bound + (right_bound - left_bound) // 2
            l2_container = &L2_CONTAINER[mid]

            # excluding left half
            if (l2_container.id < l2_id):
                left_bound = mid + 1

            # excluding right half
            elif (l2_container.id > l2_id):
                right_bound = mid - 1

            # l2.id match. returning struct value
            else:
                return l2_container.host_cat

        # L2 default
        return NO_MATCH

    cdef L2Recurve* make_l2(self, list l2_entry):
        '''allocates memory for a single L2 content struct, assigns members from l2_entry, then
        returns pointer.
        '''
        cdef L2Recurve *l2_content = <L2Recurve*>malloc(sizeof(L2Recurve))

        l2_content.id       = <uint32_t>l2_entry[0]
        l2_content.host_cat = <uint16_t>l2_entry[1]

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
            search_result = self.l1_search(host[0], host[1])

        return search_result

    cpdef void generate_structure(self, list py_trie):

        cdef:
            size_t l2_size

        # allocating memory for L1 container which is accessed by the l1_search method.
        self.L1_SIZE = len(py_trie)
        self.L1_CONTAINER = <L1Range*>malloc(sizeof(L1Range) * self.L1_SIZE)

        for i in range(self.L1_SIZE):

            l2_size = len(py_trie[i][1])

            # calling make function for l2 content struct for each entry in the current py_l2 container
            for xi in range(l2_size):
                self.L1_CONTAINER[i].l2_ptr[xi] = self.make_l2(py_trie[i][1][xi])[0]

            # assigning struct members to the current index of L1 container
            self.L1_CONTAINER[i].id = py_trie[i][0]
            self.L1_CONTAINER[i].l2_size = l2_size

            # allocating memory for individual L2 containers
            self.L1_CONTAINER[i].l2_ptr = <L2Range*>malloc(sizeof(L2Range) * l2_size)

    cdef uint32_t l1_search(self, uint32_t container_id, uint32_t host_id) nogil:

        cdef:
            size_t mid
            L1Range *l1_container
            L2Range *l2_container

            size_t left = 0
            size_t right = self.L1_SIZE

        while left <= right:
            mid = left + (right - left) // 2
            l1_container = &self.L1_CONTAINER[mid]

            # excluding left half
            if (l1_container.id < container_id):
                left = mid + 1

            # excluding right half
            elif (l1_container.id > container_id):
                right = mid - 1

            # l1.id match. iterating over l2_containers looking for l2.id match
            else:
                for i in range(l1_container.l2_size):

                    l2_container = &l1_container.l2_ptr[i]

                    if (l2_container.netid <= host_id <= l2_container.bcast):
                        return l2_container.country

                # l2 default > can probably remove and use l1 default below
                return NO_MATCH

        # l1 match
        return NO_MATCH

    cdef L2Range* make_l2(self, list l2_entry):
        '''allocates memory for a single L2 content struct, assigns members from l2_entry, then returns pointer.
        '''
        cdef L2Range *l2_content = <L2Range*>malloc(sizeof(L2Range))

        l2_content.netid   = <uint32_t>l2_entry[0]
        l2_content.bcast   = <uint32_t>l2_entry[1]
        l2_content.country = <uint16_t>l2_entry[2]

        return l2_content


# =================================================
# TYPED PYTHON STRUCTURES - keeping as alternative
# =================================================
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

                        return recursive_binary_search((hh_id, 0), recursion=<bint>1)
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
