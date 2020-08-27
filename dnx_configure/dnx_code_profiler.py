#!/usr/bin/env python3

import os as _os
import sys as _sys
import time as _time

from io import StringIO as _StringIO
from cProfile import Profile as _Profile
from pstats import Stats as _Stats, SortKey as _SortKey

HOME_DIR = _os.environ['HOME_DIR']
_sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_file_operations import append_to_file

_fast_time_ns = _time.perf_counter_ns
_CUMU = _SortKey.CUMULATIVE

# TODO: this is broken. wtf.
def profiler(*, filename):
    def decorator(thing_to_be_profiled):
        def wrapper(*args, **kwargs):
            pr = _Profile(_fast_time_ns)
            pr.enable()

            #profiled function
            thing_to_be_profiled(*args, **kwargs)

            pr.disable()
            s = _StringIO()

            ps = _Stats(pr, stream=s).sort_stats(_CUMU)
            ps.print_stats()

            message = ''.join(['='*10, 'FUNCTION START', '='*10, '\n'])

            append_to_file(message, filename, filepath='dnx_system/profiler_results')
            append_to_file(s.getvalue(), filename, filepath='dnx_system/profiler_results')

        return wrapper
    return decorator
