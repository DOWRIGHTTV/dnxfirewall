#!/usr/bin/env python3

# LABEL: DEVELOPMENT_ONLY_CODE

from __future__ import annotations

import time as _time

from typing import Callable
from io import StringIO as _StringIO
from cProfile import Profile as _Profile
from pstats import Stats as _Stats, SortKey as _SortKey

from dnx_gentools.file_operations import append_to_file

_fast_time_ns = _time.perf_counter_ns
_CUMU = _SortKey.CUMULATIVE

def dnx_profile(func: Callable, *args, filename: str, **kwargs):
    '''profiles referenced function and saves results to specified file.

        path->dnx_profile/log/_tests/**filename**.cprofile
    '''
    with _Profile(timer=_fast_time_ns, timeunit=0.000000001) as pr:
        func(*args, **kwargs)

    s = _StringIO()

    ps = _Stats(pr, stream=s).sort_stats(_CUMU)
    ps.print_stats()

    message = ''.join(['='*10, 'RUN START', '='*10, '\n'])

    append_to_file(message, f'{filename}.profile', filepath='dnx_profile/log/_tests')
    append_to_file(s.getvalue(), f'{filename}.profile', filepath='dnx_profile/log/_tests')
