
import threading as _threading

from functools import lru_cache

def generate_recursive_binary_search(tuple signatures, tuple bounds):

    cdef tuple sigs = signatures
    cdef tuple bin_match = (0,0)

    cdef object recursion_lock = _threading.Lock()

    @lru_cache(maxsize=1024)
    def recursive_binary_search(tuple host, int recursion=0):
        nonlocal bin_match

        cdef int hb_id, hh_id
        hb_id, hh_id = host

        cdef int b_id, mid

        cdef int left, right


        cdef tuple h_ranges
        cdef int host_match

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
                return 0

        else:
            # assigning bounds of the items in the bin found in the first search
            left, right = 0, len(bin_match)-1

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
                return 0

    return recursive_binary_search

def generate_linear_binary_search(tuple sigs, tuple bounds):

    @lru_cache(maxsize=1024)
    def linear_binary_search(tuple host):

        cdef int hb_id, h_id
        hb_id, h_id = host

        cdef int left, right
        left, right = bounds

        cdef int b_id, mid, r_start, r_end, c_code
        cdef tuple h_ranges

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
                for r_start, r_end, c_code in h_ranges:
                    if r_start <= h_id <= r_end:
                        return c_code
        else:
            return 0

    return linear_binary_search
