#!/usr/bin/env python3

import os, sys

import cProfile, pstats, io

from pstats import SortKey

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_file_operations import append_to_file

FILENAME = 'ip_proxy.profile'

def profiler(thing_to_be_profiled):
    def wrapper(*args, **kwargs):
        pr = cProfile.Profile()
        pr.enable()

        #profiled function
        thing_to_be_profiled(*args, **kwargs)

        pr.disable()
        s = io.StringIO()
        sortby = SortKey.CUMULATIVE
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats()

        append_to_file('='*10+'FUNCTION START'+'='*10+'\n', FILENAME, folder='dnx_system/profiler_results')
        append_to_file(s.getvalue(), FILENAME, folder='dnx_system/profiler_results')

    return wrapper