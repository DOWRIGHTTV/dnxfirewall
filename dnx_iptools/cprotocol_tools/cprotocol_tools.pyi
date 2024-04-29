from typing import ByteString

def default_route() -> int:
    '''return default route of the system.

    return 0 if a default route is not configured.
    '''
    ...
def btoia(cb: ByteString) -> int:
    '''convert a bytestring with a length of 1-4 to a 32-bit unsigned integer.

        b'\xff\xff\xff\xff' > 4294967295
    '''
    ...
def iptoi(ipa: str) -> int:
    '''convert an ip address in dot notation to a 32-bit unsigned integer.

        '127.0.0.1' > 2130706433
    '''
    ...
def itoip(ipa: int) -> str:
    '''convert 32-bit unsigned integer to ip address in dot notation.

        2130706433 > '127.0.0.1'
    '''
    ...
def hextoip(hipa: str) -> str:
    '''convert 8-byte/ (4) 2-byte char hex string to ip address in dot notation.

        "00454545" > '69.69.69.0'

    note: expecting big endian (network order) hex string.
    '''
    ...
def calc_checksum(data: ByteString) -> bytes:
    '''calculate the tcp/ip checksum of a bytestring.

    valid lengths are between 1-65535 (max length of a tcp/ip packet).
    return will be a 2-byte length bytestring.
    '''
    ...
