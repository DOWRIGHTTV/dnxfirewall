#!/usr/bin/python3

import os
import subprocess
from iptables import *

class Main_Start:
    def __init__(self):
        print("Dad's Next Gen Firewall. The First Python Firewall ;)")
        print('[1] Initial Setup')
        print('[2] Run Firewall')
        print('[3] Edit Firewall Options')
        print('[4] NGFW-X Setting ;)')
        
    def Main(self):
        self.answeR = input('Select option: ')
        if (int(self.answeR) == 1):
#            CFG = FirewallOptions()
#            IPT = IPTables()
#            CFG.Start()
#            IPT.Start()
            pass
        elif (int(self.answeR) == 2):
            import dnx_run as Firewall
            Firewall.Run()
        elif (int(self.answeR) == 3):
            exit(3)
        elif (int(self.answeR) == 4):
            exit(3)
        else:
            print('Not a valid selection. Try again.')
            self.Main()
        
if __name__ == '__main__':
    try:
        priV = os.geteuid()
        if (priV == 0):
            print(' ______   __    _  __   __    _______  _     _  _______  ___      ___     ')
            print('|      | |  |  | ||  |_|  |  |       || | _ | ||   _   ||   |    |   |    ')
            print('|  _    ||   |_| ||       |  |    ___|| || || ||  |_|  ||   |    |   |    ')
            print('| | |   ||       ||       |  |   |___ |       ||       ||   |    |   |    ')
            print('| |_|   ||  _    | |     |   |    ___||       ||       ||   |___ |   |___ ')
            print('|       || | |   ||   _   |  |   |    |   _   ||   _   ||       ||       |')
            print('|______| |_|  |__||__| |__|  |___|    |__| |__||__| |__||_______||_______|')
            MS = Main_Start()
            MS.Main()
        else:
            print('DNX FWALL requires Root Priveledges. Exiting...')
            exit(1)
    except Exception as E:
        print(E)
    except KeyboardInterrupt:
        print('\n-----------------------------------------------------')
        print("User Interrupt. Exiting Some Random Thing")
        print('-----------------------------------------------------')
