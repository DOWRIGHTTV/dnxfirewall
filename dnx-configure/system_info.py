#!/usr/bin/python3


from collections import OrderedDict
from subprocess import check_output
import datetime
import json

class Interface:
    def __init__(self):
        self.path = './data'
        
    def IP(self, interface):
        output = check_output('ifconfig {}'.format(interface), shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if('inet6' in line):
                pass
            elif('inet' in line):
                line = line.strip().split(' ')
                ip = line[1]
#                print(ip)
                return(ip)

    def MTU(self, interface):
        i = 0
        output = check_output('ifconfig {}'.format(interface), shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if(i == 0):
                i += 1
                line = line.strip().split(' ')
                mtu = line[4]
#                print(mtu)
                return(mtu)

    def Netmask(self, interface):
        output = check_output('ifconfig {}'.format(interface), shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if('inet6' in line):
                pass        
            elif('netmask' in line):
                line = line.strip().split(' ')
                netmask = line[4]
#                print(netmask)
                return(netmask)

    def Broadcast(self, interface):
        output = check_output('ifconfig {}'.format(interface), shell=True).decode()
        output = output.splitlines(8)
        for line in output:
            if('inet6' in line):
                pass        
            elif('broadcast' in line):
                line = line.strip().split(' ')
                broadcast = line[7]
#                print(broadcast)
                return(broadcast)

    def Bandwidth(self):
        intstat = {}
        with open('{}/interface_speed.json'.format(self.path), 'r') as speed:
            bandwidth = json.load(speed)
        for key, value in bandwidth.items():
            intstat[key] = [round(int(value[0])*8/1024, 2), round(int(value[1])*8/1024, 2)]

#        print(intstat)
        return intstat
        
class System:
    def __init__(self):
        self.path = './data'
        
    def CPU(self):
        with open('/proc/stat', 'r') as CPU:
            for i, line in enumerate(CPU):
                if (i == 0):         
                    line = line.split()
                    idle = int(line[4])
                    b = 0
                    for entry in line:
                        if 'cpu' not in entry:
                            b += int(entry)
                    idle *= 100
                    idle /= b
                utilization = '{}%'.format(round(100 - idle, 2))
#        print(utilization)
        return utilization
                    

    def Uptime(self):
        with open('/proc/uptime', 'r') as uptime:
            for line in uptime:       
                uptime = line.split()[0]
                uptime = datetime.timedelta(0, int(float(uptime)))
                utime = str(uptime).split()
                if ('day' in str(uptime) or 'days' in str(uptime)):         
                    uptime = '{} days {} hours {} minutes'.format(\
                    utime[0], utime[2].split(':')[0], utime[2].split(':')[1])
                else:
                    uptime = '{} days {} hours {} minutes'.format(\
                    0, utime[0].split(':')[0], utime[0].split(':')[1])
#        print(uptime)
        return uptime
            
    def RAM(self):
        meminfo = []     
        with open('/proc/meminfo', 'r') as RAM:
            for i, line in enumerate(RAM, 1):
                if (i == 1 or i == 3):
                    usage = line.split()[1]
                    meminfo.append(usage)
                    
        ram = round(int(meminfo[1]) / int(meminfo[0]) * 100, 1)            
        ram = '{}%'.format(ram)
#        print(ram)
        return(ram)
    
    def DNSStatus(self):
        with open('{}/dnsstatus.json'.format(self.path)) as dnsstat:
            dnsstatus = json.load(dnsstat)
#        print(dnsstatus)
        return dnsstatus
    
    def FirewallRules(self):
        firewallrules = OrderedDict()
        output = check_output('sudo iptables -nL FIREWALL --line-number', shell=True).decode()
        output = output.splitlines()
        for i, rules in enumerate(output, 1):
            if ('RETURN' in rules):
                pass
            elif (i not in {1,2}):
                opt_list = []
                rule = rules.split()
                for i, option in enumerate(rule):
                    if (i in {7}):
                        option = option.split(':')[1]
                        opt_list.append(option)
                    elif (i not in {0,2,3}):
                        opt_list.append(option)
                if len(opt_list) == 3:
                    opt_list.append('any')
                    opt_list.append('any')
                firewallrules[rule[0]] = opt_list
                   
        print(firewallrules)
        return(firewallrules)
        
    def NATRules(self):
        natrules = OrderedDict()
        output = check_output('sudo iptables -t nat -nL PREROUTING --line-number', shell=True).decode()
        output = output.splitlines()
        for i, rule in enumerate(output, 1):
            if (i > 2):
                rule = rule.split()
                hostinfo = rule[8].split(':')
                host_ip = hostinfo[1]
                host_port = hostinfo[2]
                dport = rule[7].split(':')[1]
                proto = rule[6]
                
                natrules[rule[0]] = [proto, dport, host_ip, host_port]
        
#        print(natrules)
        return(natrules)    
            
                                
if __name__ == '__main__':
    Int = Interface()
    Sys = System()
#    Int.IP(INIFACE)
#    Int.MTU(INIFACE)
#    Int.Netmask(INIFACE)
#    Int.Broadcast(INIFACE)
#    Int.Bandwidth()
#    Sys.CPU()
#    Sys.Uptime()
#    Sys.RAM()
#    Sys.DNSStatus()
    Sys.FirewallRules()  
#    Sys.NATRules() 

