#!/usr/bin/env python3

import os, sys
import json

path = os.environ['HOME_DIR']
sys.path.insert(0, path)

from tls_proxy.tls_sniffer import Sniffer

class TLSProxy:
    def __init__(self):
        self.path = os.environ['HOME_DIR']

        with open('{}/data/config.json'.format(self.path), 'r') as settings:
            self.setting = json.load(settings)
                                
        self.iface = self.setting['Settings']['Interface']['Inside']  

    def Start(self):
        self.Proxy()

    def Proxy(self):
        Proxy = Sniffer(self.iface, action=self.SignatureCheck)
        Proxy.Start()

    def SignatureCheck(self, packet, ssl):
        print('/'*30)
        print('SIGNATURE CHECK')
        print(packet.dport)
        print(packet.sport)        
        print('CERTIFICATE: {}'.format(ssl.certificate_chain))
        print('/'*30)


if __name__ == '__main__':
    TLSP = TLSProxy()
    TLSP.Start()
