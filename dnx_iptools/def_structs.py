#!/usr/bin/env python3

from struct import Struct as _Struct

short_unpackf = _Struct('!H').unpack_from

short_unpack = _Struct('!H').unpack
long_unpack  = _Struct('!L').unpack
byte_pack    = _Struct('!B').pack
short_pack   = _Struct('!H').pack
long_pack    = _Struct('!L').pack
int_unpack   = _Struct('I').unpack

double_bite_unpack = _Struct('!2B').unpack_from
double_short_unpack = _Struct('!2H').unpack_from
double_byte_pack  = _Struct('!2B').pack
double_short_pack = _Struct('!2H').pack

checksum_pack = _Struct('<H').pack
fcntl_pack = _Struct('24s').pack

mac_unpack = _Struct('!6s').unpack
mac_pack   = _Struct('!6s').pack

eth_header_pack    = _Struct('!6s6sH').pack
ip_header_pack     = _Struct('!2B3H2B2s4s4s').pack
udp_header_pack    = _Struct('!4H').pack
icmp_header_pack   = _Struct('!2B2s2H').pack
tcp_header_pack    = _Struct('!2H2L2BH2sH').pack
pseudo_header_pack = _Struct('!4s4s2BH').pack
ip_header_override_pack = _Struct('!10s2s4s4s').pack

eth_header_unpack = _Struct('!6s6sH').unpack_from
ip_header_unpack  = _Struct('!2B3H2B').unpack_from
tcp_header_unpack = _Struct('!2H2LB').unpack_from
udp_header_unpack = _Struct('!4H').unpack_from

dhcp_opt_unpack  = _Struct('!2B').unpack
dhcp_header_pack = _Struct('!4B4s2H4s4s4s4s16s12s180s4B').pack
dhcp_byte_pack   = _Struct('!3B').pack
dhcp_short_pack  = _Struct('!2BH').pack
dhcp_long_pack   = _Struct('!2BL').pack
dhcp_ip_pack     = _Struct('!2B4s').pack

dns_header_unpack = _Struct('!6H').unpack
dns_header_pack   = _Struct('!6H').pack
resource_record_pack = _Struct('!3HLH4s').pack

tls_unpack = _Struct('!B2HB').unpack_from
handshake_unpack = _Struct('!2B2H').unpack_from
cert_len_unpack = _Struct('!H').unpack_from

dnx_header_unpack = _Struct('!2B2H').unpack_from
dnx_header_pack   = _Struct('!2B2H').pack