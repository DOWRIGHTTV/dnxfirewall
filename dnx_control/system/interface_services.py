#!/usr/bin/env python3

from __future__ import annotations

from time import sleep
from json import dump
from subprocess import check_output

from dnx_gentools.def_constants import INITIALIZE_MODULE, HOME_DIR, NO_DELAY
from dnx_routines.logging.log_client import LogHandler as Log

from dnx_gentools.standard_tools import looper


dt = {}
INT_BANDWIDTH_TIMER = 5
SAVE_FILE = f'{HOME_DIR}/dnx_profile/data/interface_speed.cfg'

@looper(NO_DELAY)
# TODO: figure out how to revert interface values to zero if they are not detected in the output dict.
#  this would happen if interface is unplugged, but the front end would show last logged speed amount.
def interface_bandwidth(int=int, open=open):
    dx = get_current_bytes()

    sleep(INT_BANDWIDTH_TIMER)
    dy = get_current_bytes()

    if (not dx or not dy):
        return

    for k in dy:
        intf = k
        if ('@' in k):  # TODO: what is this even doing? im assuming the k below should reference intf?
            intf = k.split('@')[0]

        dt[intf] = [
            (int(dy[k][0]) - int(dx[k][0]))/INT_BANDWIDTH_TIMER, (int(dy[k][1]) - int(dx[k][1]))/INT_BANDWIDTH_TIMER
        ]

    # consider marking this stored in memory with a basic socket service listening and will return the information upon
    # request instead of doing all this unnecessary disk io. (especially since this function is only used by front end)
    with open(SAVE_FILE, 'w') as f:
        dump(dt, f)

def get_current_bytes():
    try:
        return {
            iface[0][1][:-1]:[iface[3][1], iface[5][1]] for iface in [
                [y.split() for y in x.split('\\')]
                    for x in check_output('ip -s -o link', shell=True).decode().splitlines()
            if 'lo' not in x]
        }
    except Exception as E:
        Log.simple_write('system', 'error', f'Interface bandwidth module error | {E}')
        sleep(1)


def run():
    interface_bandwidth()


if INITIALIZE_MODULE('interface'):
    pass
