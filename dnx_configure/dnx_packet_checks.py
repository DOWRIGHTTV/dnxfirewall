#!/usr/bin/ env python3

import array

class Checksums:
    def IPv4(self, header):
        if len(header) & 1:
            header = header + '\0'
        words = array.array('h', header)
        sum = 0
        for word in words:
            sum = sum + (word & 0xffff)
        hi = sum >> 16
        lo = sum & 0xffff
        sum = hi + lo
        sum = sum + (sum >> 16)

        return (~sum) & 0xffff

    def TCP(self, msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            if ((i+1) < len(msg)):
                a = msg[i]
                b = msg[i+1]
                s = s + (a+(b << 8))            
            elif ((i+1) == len(msg)):
                s += msg[i]

        s = s + (s >> 16)
        s = ~s & 0xffff

        return s