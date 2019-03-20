#!/usr/bin/python3

catlist = ['Malicious', 'VPN', 'Adult', 'Drugs', 'Guns', 'DynDNS', 'Ads', 'SocialMedia', 'TeenTop50']

combinefiles = []

def Combine():
    for cat in catlist:
        with open('config.py', 'r') as config:
            for line in config:
                if ('{}=1'.format(cat.upper()) in line):
                    combinefiles.append('{}.domains'.format(cat))

    with open('domainlists/Blocked.domains', 'w+') as Blocked:
        for files in combinefiles:
            with open('domainlists/{}'.format(files), 'r+') as files:
                for line in files:
                    Blocked.write(line)



if __name__ == '__main__':
    Combine()                
