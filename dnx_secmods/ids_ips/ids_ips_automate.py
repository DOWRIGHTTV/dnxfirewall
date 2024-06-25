#!/usr/bin/env python3

from __future__ import annotations

from typing import NamedTuple
from dataclasses import dataclass
from dataclasses import dataclass

from dnx_gentools.def_exceptions import dnx_assert
from dnx_gentools.def_constants import TYPE_CHECKING, FIVE_MIN, ONE_HOUR, NO_DELAY
from dnx_gentools.def_enums import NETWORK_PROTOCOL, PROTO_TCP, PROTO_UDP, PROTO_ICMP
from dnx_gentools.system_info import System
from dnx_gentools.standard_tools import looper, ConfigurationMixinBase
from dnx_gentools.file_operations import cfg_read_poller, ConfigurationManager

from dnx_iptools.cprotocol_tools import iptoi
from dnx_iptools.iptables import IPTablesManager

from ids_ips_log import Log

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_gentools.def_typing import ClassVar
    from dnx_gentools.def_typing import ConfigChain, OPEN_WAN_PORTS

    from dnx_routines.logging import LogHandler_T

# needed for updating pbl early removal notification in cfg
ConfigurationManager.set_log_reference(Log)

PROFILE_CT = 15

@dataclass
class PROFILE_OPTIONS:
    ids_mode: int = 0  # TODO: this should probably [maybe] be reworked.
    ddos_enabled: int = 0
    pscan_enabled: int = 0
    pscan_reject: int = 0
    all_enabled: int = 0
    block_length: int = 0

class CFG_PROFILE(NamedTuple):
    '''idx: int -> so the profile can be identified after dereferencing.
    ip_whitelist: set[int]

    ddos_limits: dict[PROTO, int]

    ids_mode:      int = 0
    ddos_enabled:  int = 0
    pscan_enabled: int = 0
    pscan_reject:  int = 0
    all_enabled:   int = 0
    block_length:  int = 0
    '''
    idx: int
    ip_whitelist: set[int]

    ddos_limits: dict[NETWORK_PROTOCOL, int]

    opt: PROFILE_OPTIONS

class IPSConfiguration(ConfigurationMixinBase):
    '''IDS/IPS configuration Mixin.
    '''
    open_ports: ClassVar[OPEN_WAN_PORTS] = {}
    fw_rules: ClassVar[dict[int, tuple[int, int]]] = {}  # this is shared across all profiles

    cfg_profiles: ClassVar[tuple[CFG_PROFILE, ...]] = tuple(
        CFG_PROFILE(
            i, set(), {PROTO_TCP: -1, PROTO_UDP: -1, PROTO_ICMP: -1}
        ) for i in range(PROFILE_CT+1)  # note: +1 is to allow for [1] start index. [0] is reserved for the system.
    )

    def _configure(self) -> tuple[LogHandler_T, tuple, int]:
        '''tasks required by the IDS/IPS.

        return thread information to be run.
        '''
        self.__class__.fw_rules = {x[0]: (x[1], x[2]) for x in System.ips_passively_blocked()}

        threads = (
            (self._get_settings, ()),
            (self._get_open_ports, ()),
            (self._passively_blocked_timeout, ())
        )

        return Log, threads, 2

    @cfg_read_poller('profiles/profile_x', profiles=(1, 15), cfg_type='security/ids_ips')
    def _get_settings(self, profile_idx: int, proxy_settings: ConfigChain) -> None:

        cfg_profile: CFG_PROFILE = self.__class__.cfg_profiles[profile_idx]

        # GENERAL CFG FLAGS
        # ===================================================
        cfg_profile.opt.ids_mode = proxy_settings['ids_mode']
        cfg_profile.opt.ddos_enabled = proxy_settings['ddos->enabled']
        cfg_profile.opt.pscan_enabled = proxy_settings['port_scan->enabled']
        cfg_profile.opt.pscan_reject  = proxy_settings['port_scan->reject']
        cfg_profile.opt.all_enabled = proxy_settings['ddos->enabled'] and proxy_settings['port_scan->enabled']
        if (cfg_profile.opt.ddos_enabled and not cfg_profile.opt.ids_mode):

            # checking length(hours) to leave IP table rules in place for hosts part of ddos attacks
            # note: minimum of 5 minutes to prevent active attackers from being cleared too soon.
            cfg_profile.opt.block_length = max(FIVE_MIN, proxy_settings['passive_block_ttl']) * ONE_HOUR

        # if ddos engine is disabled
        else:
            self.__class__.block_length = NO_DELAY

        # IDS/IPS PROFILE SETTINGS
        # ===================================================
        # ddos CPS configured thresholds
        cfg_profile.ddos_limits[PROTO_ICMP] = proxy_settings['ddos->limits->source->icmp']
        cfg_profile.ddos_limits[PROTO_TCP]  = proxy_settings['ddos->limits->source->tcp']
        cfg_profile.ddos_limits[PROTO_UDP]  = proxy_settings['ddos->limits->source->udp']

        # !assert: make sure this is working as intended.
        #   the resulting set should have only the currently configured ip addresses.
        # source ip addresses in this set will not trigger ids/ips rules.
        cfg_ip_whitelist = set([iptoi(ip) for ip in proxy_settings['whitelist->ip_whitelist']])

        cfg_profile.ip_whitelist.intersection_update(cfg_ip_whitelist)

        dnx_assert(
            cfg_profile.ip_whitelist == cfg_ip_whitelist, 'IP whitelist in memory does not match config.', logger=Log
        )

        self._initialize.done()

    # todo: determine whether the default sleep timer is acceptable for this open port updates. if not, figure out how
    #  to override the setting set in the decorator or remove the decorator entirely.
    @cfg_read_poller('global', cfg_type='security/ids_ips')
    def _get_open_ports(self, proxy_settings: ConfigChain) -> None:

        self.__class__.open_ports = {
            PROTO_TCP: {
                int(local_p): int(wan_p) for wan_p, local_p in proxy_settings.get_items('open_protocols->tcp')
            },
            PROTO_UDP: {
                int(local_p): int(wan_p) for wan_p, local_p in proxy_settings.get_items('open_protocols->udp')
            },
            PROTO_ICMP: {}  # note: allows for less logic when checking for open ports during packet processing.
        }

        # note: this is needed to remove hosts from memory that were manually removed by a user via webui
        if hosts_to_remove := proxy_settings.get_items('pbl_remove'):
            with ConfigurationManager('global', cfg_type='security/ids_ips') as dnx:
                ips_global_settings: ConfigChain = dnx.load_configuration(strict=False)

                for host, timestamp in hosts_to_remove:
                    # removing host from ips tracker/ suppression dictionary
                    # notify list could desync from in memory tracker under service/system shutdown conditions, so we
                    # will remove entry from the "notify" list regardless.
                    self.__class__.fw_rules.pop(int(host), None)

                    del ips_global_settings[f'pbl_remove->{host}']

                dnx.write_configuration(ips_global_settings.expanded_user_data)

        self._initialize.done()

    def _passively_blocked_load(self):
        pass

    @looper(FIVE_MIN)
    # refactored function utilizing iptables + profile + timestamp comment to identify rules to be expired.
    # this makes the passive blocking system persist service or system reboots.
    # !test: make sure removal is being properly applied to the specific profile and correct expiration time.
    def _passively_blocked_timeout(self) -> None:
        for profile in self.__class__.cfg_profiles:

            expired_hosts = System.ips_passively_blocked(profile_idx=profile.idx, block_length=profile.block_length)
            if (not expired_hosts):
                continue

            with IPTablesManager() as iptables:
                for host, timestamp in expired_hosts:
                    iptables.remove_passive_block(host, profile.idx, timestamp)

                    # removing host from ips tracker/ suppression dictionary
                    self.__class__.fw_rules.pop(host, None)  # should never return None
