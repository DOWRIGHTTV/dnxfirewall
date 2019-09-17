#!/usr/bin/env python3

import os, sys
import time
import json
import asyncio

from datetime import datetime

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import *
from dnx_configure.dnx_configure import System
from dnx_configure.dnx_iptables import IPTables

class IPTimer:
    def __init__(self):
        self.restriction_active = False

    async def Start(self):
        start, _, restriction = await self.CalculateTimes()
        await self.CalculateEndTime(start, restriction)

        await self.SetTimer()

    async def Settings(self):
        # Offset settings, configured by user
        while True:
            with open(f'{HOME_DIR}/data/config.json', 'r') as configs:
                config = json.load(configs)

            o_s = config['settings']['time_offset']
            os_direction = o_s['direction']
            os_amount = o_s['amount']

            offset = int(f'{os_direction}{os_amount}')
            self.offset = offset * 3600

            await asyncio.sleep(SETTINGS_TIMER)

    async def SetTimer(self):
        loop = asyncio.get_running_loop()
        ## -------------------------------------------##
        ## --         TIME RESTRICTION CHECK       -- ##
        while True:
            start, now, restriction = await self.CalculateTimes()
            restriction_enabled = restriction['enabled']
            end = restriction['end']

            if (restriction_enabled):
                if (not self.restriction_active):
                    if (now > start):
                        self.restriction_active = True
                        #make ip tables rule
                        IPT = IPTables()
#                        IPT.AdjustRestrictionTimer(action=True)
                        await loop.run_in_executor(None, IPT.AdjustRestrictionTimer, True)
                        IPT.Commit()
#                        print('time restriction in effect')

            if (self.restriction_active):
                if (now > end):
                    self.restriction_active = False
                    await self.CalculateEndTime(start, restriction)
                    # remove ip tables rule
                    IPT = IPTables()
#                    IPT.AdjustRestrictionTimer(action=False)
                    await loop.run_in_executor(None, IPT.AdjustRestrictionTimer, False)
                    IPT.Commit()
#                    print('removing time restriction')

            await asyncio.sleep(SETTINGS_TIMER)

    async def LoadRestriction(self):
        with open(f'{HOME_DIR}/data/config.json', 'r') as restrictions:
            self.restriction = json.load(restrictions)
        restriction = self.restriction['settings']['time_restriction']

        return restriction

    # Calculating what the current date and time is and what the current days start time is in epoch
    # this must be calculated daily as the start time epoch is always changing
    async def CalculateTimes(self):
        Sys = System()
        c_d = Sys.Date() # current date
        c_t = Sys.Time() # current time
        c_d = [int(i) for i in c_d]
        c_t = [int(i) for i in c_t]

        restriction = await self.LoadRestriction()

        start = restriction['start'].split(':')
        start = [int(i) for i in start]

        start = datetime(c_d[0], c_d[1], c_d[2], start[0], start[1]).timestamp()
        now = datetime(c_d[0], c_d[1], c_d[2], c_t[0], c_t[1]).timestamp()

        return start, now, restriction

    # Calculating the time.time() of when timer should end. calculated by current days start time (time since epoch)
    # and then adding seconds of user configured amount to start time.
    async def CalculateEndTime(self, start, restriction):
        end = start + restriction['length']

        restriction.update({'end': end})

        with open(f'{HOME_DIR}/data/config.json', 'w') as restrictions:
            json.dump(self.restriction, restrictions, indent=4)
