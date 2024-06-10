#!/usr/bin/env python3

from __future__ import annotations

from typing import NamedTuple

from dnx_gentools.def_constants import TYPE_CHECKING, RFC1918
from dnx_gentools.def_namedtuples import Item
from dnx_gentools.def_enums import DIRECTION, GEO, GEOLOCATION, REP, REPUTATION
from dnx_gentools.def_enums import PROTO_UDP, PROTO_TCP
from dnx_gentools.standard_tools import ConfigurationMixinBase
from dnx_gentools.file_operations import cfg_read_poller

from dnx_iptools.iptables import IPTablesManager

from ip_proxy_log import Log

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_typing import ClassVar
    from dnx_gentools.def_typing import ConfigChain, OPEN_WAN_PORTS

    from dnx_routines.logging import LogHandler_T

PROFILE_CT = 15

class CFG_PROFILE(NamedTuple):
    '''idx: int -> so the profile can be identified after dereferencing.
    geolocation_settings: dict[GEOLOCATION, DIRECTION]
    reputation_settings: dict[REPUTATION, DIRECTION]

    ip_whitelist: dict
    tor_whitelist: dict

    ids_mode: int = 0
    '''
    idx: int

    geolocation_settings: dict[GEOLOCATION, DIRECTION]
    reputation_settings:  dict[REPUTATION, DIRECTION]

    ip_whitelist:  dict
    tor_whitelist: dict

    ids_mode: int = 0

class ProxyConfiguration(ConfigurationMixinBase):
    '''IP proxy configuration Mixin.
    '''
    open_ports: ClassVar[OPEN_WAN_PORTS] = {  # this is shared across all profiles | used for wan response
        PROTO_TCP: {},
        PROTO_UDP: {}
    }

    cfg_profiles: ClassVar[tuple[CFG_PROFILE, ...]] = tuple(
        CFG_PROFILE(
            i, {}, {}, {}, {}
        ) for i in range(PROFILE_CT+1)  # note: +1 is to allow for [1] start index. [0] is reserved for the system.
    )

    def _configure(self) -> tuple[LogHandler_T, tuple, int]:
        '''tasks required by the IP proxy.

        return thread information to be run.
        '''
        self._manage_ip_tables()

        threads = (
            (self._get_settings, ()),
            # (self._get_ip_whitelist, ()),
            (self._get_open_ports, ())
        )

        return Log, threads, len(threads)

    @cfg_read_poller('profiles/profile_x', cfg_type='security/ip')
    def _get_settings(self, profile_idx: int, proxy_settings: ConfigChain) -> None:

        cfg_profile: CFG_PROFILE = self.__class__.cfg_profiles[profile_idx]

        cfg_profile.ids_mode = proxy_settings['ids_mode']

        # REPUTATION SETTINGS
        rep_settings = proxy_settings.get_items('reputation->built-in')

        for reputation, direction in rep_settings:

            reputation_name = reputation.upper()

            # membership test to detect potential critical errors in signature handling
            try:
                REP[reputation_name]
            except KeyError:
                Log.error(f'reputation category [{reputation_name}] not found in REPUTATION enum')
            else:
                cfg_profile.reputation_settings[reputation_name] = DIRECTION(direction)

        # GEOLOCATION SETTINGS
        geo_settings = [Item(*RFC1918)]  # used for categorizing private ip addresses

        for region in proxy_settings.get_list('geolocation'):
            geo_settings.extend(proxy_settings.get_items(f'geolocation->{region}->countries'))

        for country, direction in geo_settings:

            country_name = country.upper()

            # membership test to detect potential critical errors in signature handling
            try:
                GEO[country_name]
            except KeyError:
                Log.error(f'country [{country_name}] not found in GEOLOCATION enum')
            else:
                cfg_profile.geolocation_settings[country_name] = DIRECTION(direction)

        self._initialize.done()

    # deprecated:: ip whitelists are disabled for rework.
    # idea:: tor and general whitelist need to handled on a per profile basis.
    #  should probably just move this into the profile cfg file and update the same as rep and geo settings.
    # @cfg_read_poller('whitelist', cfg_type='global')
    # def _get_ip_whitelist(self, whitelist: ConfigChain) -> None:
    #
    #     self.__class__.ip_whitelist = {
    #         ip for ip, wl_info in whitelist.get_items('ip_bypass') if wl_info['type'] == 'ip'
    #     }
    #
    #     self.__class__.tor_whitelist = {
    #         ip for ip, wl_info in whitelist.get_items('ip_bypass') if wl_info['type'] == 'tor'
    #     }
    #
    #     self._initialize.done()

    @cfg_read_poller('global', cfg_type='security/ids_ips')
    def _get_open_ports(self, ips: ConfigChain) -> None:

        self.__class__.open_ports = {
            PROTO_TCP: {
                int(local_port): int(wan_port) for wan_port, local_port in ips.get_items('open_protocols->tcp')
            },
            PROTO_UDP: {
                int(local_port): int(wan_port) for wan_port, local_port in ips.get_items('open_protocols->udp')
            }
        }

        self._initialize.done()

    @staticmethod
    def _manage_ip_tables():
        IPTablesManager.clear_dns_over_https()
        IPTablesManager.update_dns_over_https()
