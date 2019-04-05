#!/usr/bin/env python3

class Timer:
    def __init__(self):
        self.offset = ''        
        
    def Start(self):
        start, now, _ = self.CalculateTimes()
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
                    self.CalculateEndTime(start)
                    # remove ip tables rule
        
    def LoadRestriction(self):
        with open('{}/data/config.json'.format(self.path), 'r') as restrictions:
            restriction = json.load(restrictions)                
        restriction = restriction['Settings']['TimeRestriction']
        
        return restriction
        
    def CalculateTimes(self):
        Sys = System()
        c_d = Sys.Date() # current date
        c_t = Sys.Time() # current time
        
        restriction = self.LoadRestriction()
            
        start = restriction['Start'].split(':')
        start = datetime(c_d[0], c_d[1], c_d[2], start[0], start[1]).timestamp()
        now = datetime(c_d[0], c_d[1], c_d[2], c_hour, c_min).timestamp()
        
        return start, now, restriction
        
    def CalculateEndTime(self, start, restriction):
        end = start + restriction['Length']*3600

        restriction.update({'End': end})

        with open('{}/data/config.json'.format(self.path), 'w') as restrictions:
            json.dump(restriction, restrictions, indent=4)
    
