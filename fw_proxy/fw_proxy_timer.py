#!/usr/bin/env python3

import os, sys, time
import json

from datetime import datetime

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from dnx_configure.dnx_configure import System

class Timer:
    def __init__(self):
        self.path = os.environ['HOME_DIR']
        
        self.restriction_active = False
        
        with open('{}/data/config.json'.format(self.path), 'r') as configs:
            config = json.load(configs)
        
        o_s = config['Settings']['TimeOffset']
        offset = int('{}{}'.format(o_s['Direction'], o_s['Amount']))
        self.offset = offset * 3600

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

            if (self.restriction_active):
                if (now > end):
                    self.restriction_active = False
                    self.CalculateEndTime(start, restriction)
                    # remove ip tables rule

            time.sleep(5 * 60)
        
    def LoadRestriction(self):
        with open('{}/data/config.json'.format(self.path), 'r') as restrictions:
            self.restriction = json.load(restrictions)                
        restriction = self.restriction['Settings']['TimeRestriction']
        
        return restriction
        
    def CalculateTimes(self):
        Sys = System()
        c_d = Sys.Date() # current date
        c_t = Sys.Time() # current time
        
        restriction = self.LoadRestriction()
            
        start = restriction['Start'].split(':')
        start = datetime(c_d[0], c_d[1], c_d[2], int(start[0]), int(start[1])).timestamp()
        now = datetime(c_d[0], c_d[1], c_d[2], c_t[0], c_t[1]).timestamp()
        
        return start, now, restriction
        
    def CalculateEndTime(self, start, restriction):
        end = start + restriction['Length']

        restriction.update({'End': end})

        with open('{}/data/config.json'.format(self.path), 'w') as restrictions:
            json.dump(self.restriction, restrictions, indent=4)
    
