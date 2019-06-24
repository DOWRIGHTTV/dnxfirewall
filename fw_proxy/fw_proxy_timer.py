#!/usr/bin/env python3

import os, sys, time
import json

from datetime import datetime

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_configure import System
from dnx_configure.dnx_iptables import IPTables

class Timer:
    def __init__(self):
        self.path = os.environ['HOME_DIR']

        # Offset settings, configured by user
        with open(f'{self.path}/data/config.json', 'r') as configs:
            config = json.load(configs)
        
        o_s = config['Settings']['TimeOffset']
        os_direction = o_s['Direction']
        os_amount = o_s['Amount']

        offset = int(f'{os_direction}{os_amount}')
        self.offset = offset * 3600

        self.restriction_active = False

    def Start(self):
        start, _, restriction = self.CalculateTimes()
        self.CalculateEndTime(start, restriction)
        
        self.SetTimer()

    def SetTimer(self):
       ## -------------------------------------------##
       ## --         TIME RESTRICTION CHECK       -- ##
        while True:
            start, now, restriction = self.CalculateTimes()
            restriction_enabled = restriction['Enabled']
            end = restriction['End']
            
            if (restriction_enabled):
                if (not self.restriction_active):
                    if (now > start):
                        self.restriction_active = True
                        #make ip tables rule
                        IPT = IPTables()
                        IPT.AdjustRestrictionTimer(action=True)
                        IPT.Commit()
#                        print('time restriction in effect')

            if (self.restriction_active):
                if (now > end):
                    self.restriction_active = False
                    self.CalculateEndTime(start, restriction)
                    # remove ip tables rule
                    IPT = IPTables()
                    IPT.AdjustRestrictionTimer(action=False)
                    IPT.Commit()
#                    print('removing time restriction')

            time.sleep(5 * 60)
        
    def LoadRestriction(self):
        with open(f'{self.path}/data/config.json', 'r') as restrictions:
            self.restriction = json.load(restrictions)                
        restriction = self.restriction['Settings']['TimeRestriction']
        
        return restriction
        
    # Calculating what the current date and time is and what the current days start time is in epoch
    # this must be calculated daily as the start time epoch is always changing    
    def CalculateTimes(self):
        Sys = System()
        c_d = Sys.Date() # current date
        c_t = Sys.Time() # current time
        
        restriction = self.LoadRestriction()
            
        start = restriction['Start'].split(':')
        start = datetime(c_d[0], c_d[1], c_d[2], int(start[0]), int(start[1])).timestamp()
        now = datetime(c_d[0], c_d[1], c_d[2], c_t[0], c_t[1]).timestamp()
        
        return start, now, restriction
        
    # Calculating the time.time() of when timer should end. calculated by current days start time (time since epoch)
    # and then adding seconds of user configured amount to start time.
    def CalculateEndTime(self, start, restriction):
        end = start + restriction['Length']

        restriction.update({'End': end})

        with open(f'{self.path}/data/config.json', 'w') as restrictions:
            json.dump(self.restriction, restrictions, indent=4)
    
