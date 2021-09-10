#!/usr/bin/env python3

import os, sys

from time import sleep
from json import dump
from subprocess import check_output

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-3]))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import NO_DELAY, INT_BANDWIDTH_TIMER
from dnx_gentools.standard_tools import looper
from dnx_sysmods.logging.log_main import LogHandler as Log

LOG_NAME = 'system'

dt = {}

@looper(NO_DELAY)
# TODO: figure out how to revert interface values to zero if they are not detected in the output dict.
# this would happen if interface is unplugged, but the front end would show last logged speed amount.
def interface_bandwidth():
    dx = get_current_bytes()
    # print('DX ', dx)
    sleep(INT_BANDWIDTH_TIMER)
    dy = get_current_bytes()
    # print('DY ', dy)

    if (not dx or not dy): return

    for k in dy:
        intf = k
        if ('@' in k):
            intf = k.split('@')[0]

        dt[intf] = [(int(dy[k][0]) - int(dx[k][0]))/INT_BANDWIDTH_TIMER, (int(dy[k][1]) - int(dx[k][1]))/INT_BANDWIDTH_TIMER]

    with open(f'{HOME_DIR}/dnx_system/data/interface_speed.json', 'w') as f:
        dump(dt, f)

def get_current_bytes():
    try:
        return {iface[0][1][:-1]:[iface[3][1], iface[5][1]] for iface
            in [[y.split() for y in x.split('\\')] for x in check_output('ip -s -o link', shell=True).decode().splitlines()
            if 'lo' not in x]}
    except Exception as E:
        Log.simple_write(LOG_NAME, 'error', f'Interface bandwidth module error | {E}')
        sleep(1)

if __name__ == '__main__':
    interface_bandwidth()
