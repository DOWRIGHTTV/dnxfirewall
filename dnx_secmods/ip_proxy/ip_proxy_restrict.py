#!/usr/bin/env python3

from __future__ import annotations

# TODO: move this module to cfirewall. this should be able to be implemented in the form of quotas.
#  either have it directly on the rule or use a "rule id" key pair with a quota time as value for rule to check against.

# TODO: this can and should be moved to cfirewall
# if local ip is not in the ip whitelist, the packet will be dropped while time restriction is active.
# if (LanRestrict.is_active and packet.in_zone == LAN_IN
#         and packet.src_ip not in self.ip_whitelist):
#     packet.nfqueue.drop()
#
#     return False

import threading

from datetime import datetime

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.standard_tools import looper, classproperty, Initialize
from dnx_gentools.file_operations import ConfigurationManager, load_configuration, load_data, cfg_read_poller

from dnx_gentools.system_info import System

from ip_proxy_log import Log


# required when using ConfigurationManager context manager
ConfigurationManager.set_log_reference(Log)


class LanRestrict:
    '''lan restriction management is done within this class.

    public attributes: is_enabled, is_active

    call run method to start service.

    '''
    _enabled: ClassVar[bool] = False
    _active:  ClassVar[bool] = False

    initialize: Initialize
    proxy: IPProxy_T

    __slots__ = (
        'initialize', 'proxy'
    )

    @classproperty
    def is_enabled(cls) -> bool:
        return cls._enabled

    @classproperty
    def is_active(cls) -> bool:
        return cls._active

    @classmethod
    def run(cls, proxy: IPProxy_T) -> None:
        '''initializes settings and attributes then runs timer service in a new thread before returning.
        '''
        self = cls.__new__(cls)
        self.proxy = proxy
        self.initialize = Initialize(Log, proxy.__name__)

        cls._active = load_data('ip_proxy.timer', cfg_type='security/ip')['active']

        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._tracker).start()

        self.initialize.wait_for_threads(count=2)

    @cfg_read_poller('ip', cfg_type='security/ip')
    def _get_settings(self, proxy_settings: ConfigChain) -> None:

        self.__class__._enabled = proxy_settings['time_restriction->enabled']

        self.initialize.done()

    @looper(ONE_MIN)
    def _tracker(self) -> None:
        restriction_start, restriction_end, now = self._calculate_times()

        if (not self.is_enabled and self.is_active):
            self._set_restriction_status(active=False)

        # NOTE: validate end check is doing anything. if not remove it to make code easier to deal with
        elif (self.is_enabled and not self.is_active
                and restriction_start < now < restriction_end):
            self._set_restriction_status(active=True)

            Log.notice('LAN restriction in effect.')

        elif (self.is_active and now > restriction_end):
            self._set_restriction_status(active=False)

            Log.notice('LAN restriction released.')

        self.initialize.done()

    # Calculating what the current date and time is and what the current days start time is in epoch
    # this must be calculated daily as the start time epoch is always changing
    def _calculate_times(self) -> tuple[float, float, int]:
        restriction_time, restriction_length, offset = self._load_restriction()

        now: int = fast_time() + offset

        c_d:     list[int] = [int(i) for i in System.date(now)]  # current date
        r_start: list[int] = [int(i) for i in restriction_time.split(':')]

        restriction_start: float = datetime(*c_d[:2], *r_start[:1]).timestamp()
        restriction_end:   float = restriction_start + restriction_length

        if (self.is_active):
            restriction_end: float = load_data('ip_proxy.timer', cfg_type='system/global')['end']

        else:
            self._write_end_time(restriction_end)

        return restriction_start, restriction_end, now

    # Calculating the time.time() of when timer should end. calculated by current days start time (time since epoch)
    # and then adding seconds of user configured amount to start time.
    def _write_end_time(self, restriction_end: float) -> None:
        with ConfigurationManager('ip_proxy', ext='timer') as ip_proxy:
            ip_proxy.config_data['end'] = restriction_end

    def _load_restriction(self) -> tuple[str, float, int]:
        proxy_settings: ConfigChain = load_configuration('global', cfg_type='security/ip')
        log_settings:   ConfigChain = load_configuration('logging_client')

        restriction_start:  str = proxy_settings['time_restriction->start']
        restriction_length: float = proxy_settings['time_restriction->length']

        os_direction: str = log_settings['time_offset->direction']
        os_amount:    str = log_settings['time_offset->amount']

        offset = int(f'{os_direction}{os_amount}') * ONE_DAY

        return restriction_start, restriction_length, offset

    def _set_restriction_status(self, active):
        self.__class__._active = active

        with ConfigurationManager('ip_proxy', ext='timer') as ip_proxy:
            ip_proxy.config_data['active'] = active
