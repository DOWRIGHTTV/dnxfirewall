#!/usr/bin/env python3


class DNXError(Exception):
    ''' Base error for all other DNX errors. '''

class IPProtocolError(DNXError):
    ''' Error raised when proxy detected ip protocol (eg. TCP) that is different 
    that what the specific proxy is looking for. Helps performance by halting further 
    processing of packet as soon as possible. '''
    
class TCPProtocolError(DNXError):
    ''' Error raised when proxy detected tcp protocol (eg HTTPS)that is different 
    that what the specific proxy is looking for. Helps performance by halting further 
    processing of packet as soon as possible. '''
    
class UDPProtocolError(DNXError):
    ''' Error raised when proxy detected tcp protocol (eg DNS) that is different 
    that what the specific proxy is looking for. Helps performance by halting further 
    processing of packet as soon as possible. '''
