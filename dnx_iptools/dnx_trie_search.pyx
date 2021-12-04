#!/usr/bin/env python3

from libc.stdlib cimport malloc, calloc, free

import threading as _threading

from functools import lru_cache as _lru_cache


# ================================================ #
# C STRUCTURES - converted from python tuples
# ================================================ #
cdef class RecurveTrie:

    # L1 CONTAINER = [<CONTAINER_ID, L2_CONTAINER_SIZE, L2_CONTAINER_PTR>]
    # L2 CONTAINER = [<CONTAINER_ID, HOST_CATEGORY>]

    cdef l2_recurve* make_l2(self, (long, long) l2_entry):
        '''allocates memory for a single L2 content struct, assigns members from l2_entry, then
        returns pointer.'''

        cdef l2_recurve *L2_CONTENT

        L2_CONTENT = <l2_recurve*>malloc(sizeof(l2_recurve))

        L2_CONTENT.id = l2_entry[0]
        L2_CONTENT.host_category = l2_entry[1]

        return L2_CONTENT

    def generate_structure(self, tuple py_signatures):

        # allocating memory for L1 container. this will be accessed from l1_search method.
        # L1 container will be iterated over, being checked for id match. if a match is found
        # the reference stored at that index will be used to check for l2 container id match.
        self.L1_SIZE = len(py_signatures)
        self.L1_CONTAINER = <l1_recurve*>malloc(sizeof(l1_recurve) * self.L1_SIZE)

        for i in range(self.L1_SIZE):

            # accessed via pointer stored in L1 container
            L2_SIZE = len(py_signatures[i][1])

            # allocating memory for indivual L2 containers
            L2_CONTAINER = <l2_recurve*>malloc(sizeof(l2_recurve) * L2_SIZE)

            # calling make function for l2 content struct for each entry in current py_l2 container
            for xi in range(L2_SIZE):
                L2_CONTAINER[xi] = self.make_l2(py_signatures[i][1][xi])[0]

            # assigning struct members to current index of L1 container.
            self.L1_CONTAINER[i].id = <long>py_signatures[i][0]
            self.L1_CONTAINER[i].l2_size = L2_SIZE
            self.L1_CONTAINER[i].l2_ptr = L2_CONTAINER

    @_lru_cache(maxsize=4096)
    def search(self, (long, long) host):

        cdef long search_result

        with nogil:
            search_result = self._l1_search(host)

        return search_result

    cdef long _l1_search(self, (long, long) container_ids) nogil:

        cdef:
            long left = 0
            long right = self.L1_SIZE

            long mid

            l1_recurve l1_container

        while left <= right:
            mid = left + (right - left) // 2
            l1_container = self.L1_CONTAINER[mid]

            # excluding left half
            if (l1_container.id < container_ids[0]):
                left = mid + 1

            # excluding right half
            elif (l1_container.id > container_ids[0]):
                right = mid - 1

            # l1.id match. calling l2_search with ptr to l2_containers looking for l2.id match
            else:
                return self._l2_search(container_ids[1], l1_container.l2_size, &l1_container.l2_ptr)

        # iteration completed with no l1 match
        return 0

    cdef long _l2_search(self, long container_id, short l2_size, l2_recurve **L2_CONTAINER) nogil:

        cdef:
            short left = 0
            short right = l2_size

            short mid

            l2_recurve l2_container

        while left <= right:
            mid = left + (right - left) // 2
            l2_container = L2_CONTAINER[0][mid]

            # excluding left half
            if (l2_container.id < container_id):
                left = mid + 1

            # excluding right half
            elif (l2_container.id > container_id):
                right = mid - 1

            # l2.id match. returning struct value
            else:
                return l2_container.host_category

        # iteration completed with no l2 match
        return 0


cdef class RangeTrie:

    # L1 CONTAINER = [<CONTAINER_ID, L2_CONTAINER_SIZE, L2_CONTAINER_PTR>]
    # L2 CONTAINER = [<NETWORK_ID, BROADCAST_ID, HOST_COUNTRY>]

    cdef l2_range* make_l2(self, (long, long, short) l2_entry):
        '''allocates memory for a single L2 content struct, assigns members from l2_entry, then returns pointer.'''

        cdef l2_range *L2_CONTENT

        L2_CONTENT = <l2_range*>malloc(sizeof(l2_range))

        L2_CONTENT.network_id   = l2_entry[0]
        L2_CONTENT.broadcast_id = l2_entry[1]
        L2_CONTENT.country_code = l2_entry[2]

        return L2_CONTENT

    def generate_structure(self, tuple py_signatures):

        # allocating memory for L1 container. this will be accessed from l1_search method.
        # L1 container will be iterated over, being checked for id match. if a match is found
        # the reference stored at that index will be used to check for l2 container id match.
        self.L1_SIZE = len(py_signatures)
        self.L1_CONTAINER = <l1_range*>malloc(sizeof(l1_range) * self.L1_SIZE)

        for i in range(self.L1_SIZE):

            # accessed via pointer stored in L1 container
            L2_SIZE = len(py_signatures[i][1])

            # allocating memory for indivual L2 containers
            L2_CONTAINER = <l2_range*>malloc(sizeof(l2_range) * L2_SIZE)

            # calling make function for l2 content struct for each entry in current py_l2 container
            for xi in range(L2_SIZE):
                L2_CONTAINER[xi] = self.make_l2(py_signatures[i][1][xi])[0]

            # assigning struct members to current index of L1 container
            self.L1_CONTAINER[i].id = <long>py_signatures[i][0]
            self.L1_CONTAINER[i].l2_size = L2_SIZE
            self.L1_CONTAINER[i].l2_ptr = L2_CONTAINER

    @_lru_cache(maxsize=4096)
    def search(self, (long, long) host):

        cdef long search_result

        with nogil:
            search_result = self._search(host)

        return search_result

    cdef long _search(self, (long, long) container_ids) nogil:

        cdef:
            long left = 0
            long right = self.L1_SIZE

            long mid

            l1_range l1_container
            l2_range l2_container

        while left <= right:
            mid = left + (right - left) // 2
            l1_container = self.L1_CONTAINER[mid]

            # excluding left half
            if (l1_container.id < container_ids[0]):
                left = mid + 1

            # excluding right half
            elif (l1_container.id > container_ids[0]):
                right = mid - 1

            # l1.id match. iterating over l2_containers looking for l2.id match
            else:
                for i in range(l1_container.l2_size):

                    l2_container = l1_container.l2_ptr[i]
                    if l2_container.network_id <= container_ids[1] <= l2_container.broadcast_id:
                        return l2_container.country_code

                # iteration completed with no l2 match
                return 0

        # iteration completed with no match l1 match
        return 0

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
