#!/usr/bin/env python3

import os, sys

from time import sleep
from json import dump
from subprocess import check_output

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import INT_BANDWIDTH_TIMER
from dnx_logging.log_main import LogHandler

LOG_MOD = 'system'

# TODO: figure out how to revert interface values to zero if they are not detected in the output dict.
# this would happen if interface is unplugged, but the front end would show last logged speed amount.
def interface_bandwidth():
    dt = {}
    while True:
        dx = get_current_bytes()
        print('DX ', dx)
        sleep(INT_BANDWIDTH_TIMER)
        dy = get_current_bytes()
        print('DY ', dy)

        if (not dx or not dy): continue

        for k in dy:
            intf = k
            if ('@' in k):
                intf = k.split('@')[0]
            dt[intf] = [(int(dy[k][0]) - int(dx[k][0]))/INT_BANDWIDTH_TIMER, (int(dy[k][1]) - int(dx[k][1]))/INT_BANDWIDTH_TIMER]

        with open(f'{HOME_DIR}/data/interface_speed.json', 'w') as f:
            dump(dt, f)

def get_current_bytes():
    try:
        return {iface[0][1][:-1]:[iface[3][1], iface[5][1]] for iface
            in [[y.split() for y in x.split('\\')] for x in check_output('ip -s -o link', shell=True).decode().splitlines() \
            if 'wan' in x or 'lan' in x]}
    except Exception as E:
        Log = LogHandler(module=LOG_MOD)
        Log.message(f'Interface bandwidth module error | {E}')

if __name__ == '__main__':
    interface_bandwidth()
