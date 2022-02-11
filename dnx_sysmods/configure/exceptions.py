#!/usr/bin/env python3

class DNXError(Exception):
    '''Base error for all other DNX errors. '''

class IPProtocolError(DNXError):
    '''Error raised when proxy detected ip protocol (eg. TCP) that is different
    that what the specific proxy is looking for. Helps performance by halting further
    processing of packet as soon as possible. '''

class TCPProtocolError(DNXError):
    '''Error raised when proxy detected tcp protocol (eg HTTPS)that is different
    that what the specific proxy is looking for. Helps performance by halting further
    processing of packet as soon as possible. '''

class UDPProtocolError(DNXError):
    '''Error raised when proxy detected tcp protocol (eg DNS) that is different
    that what the specific proxy is looking for. Helps performance by halting further
    processing of packet as soon as possible. '''

class DNSProtocolError(DNXError):
    '''Error raised when proxy detected DNS protocol, but DNS message type is not type
    1 which indicates the client is doing an ipv4 query. '''

class DNXProtocolError(DNXError):
    '''Base error raised when licence/update client.'''

class ChecksumMismatch(DNXProtocolError):
    '''Error raised when DNX protocol header checksum does not match the calculated checksum.'''

class ValidationError(DNXError):
    '''Error raised when front end validations fail to notify the user/front end there
    was a problem and provide a message of what happened. '''