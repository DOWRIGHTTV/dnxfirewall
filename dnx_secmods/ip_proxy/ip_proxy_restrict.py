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
from dnx_gentools.file_operations import load_configuration, cfg_read_poller, ConfigurationManager

from dnx_routines.configure.system_info import System

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

    __slots__ = (
        'initialize', 'ip_proxy'
    )

    def __init__(self, name):
        self.initialize = Initialize(Log, name)

    @classproperty
    def is_enabled(cls) -> bool:
        return cls._enabled

    @classproperty
    def is_active(cls) -> bool:
        return cls._active

    @classmethod
    def run(cls, ip_proxy: IPProxy) -> None:
        '''initializes settings and attributes then runs timer service in a new thread before returning.
        '''
        self = cls(ip_proxy.__name__)
        self.ip_proxy = ip_proxy

        cls._active = load_data('ip_proxy.timer')['active']

        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._tracker).start()

        self.initialize.wait_for_threads(count=2)

    @cfg_read_poller('ip_proxy')
    def _get_settings(self, cfg_file):
        proxy_settings = load_configuration(cfg_file)

        self.__class__._enabled = proxy_settings['time_restriction->enabled']

        self.initialize.done()

    @looper(ONE_MIN)
    def _tracker(self):
        restriction_start, restriction_end, now = self._calculate_times()

        # Log.debug(f'ENABLED: {self.is_enabled} | ACTIVE: {self.is_active}')
        # Log.debug(f'START: {restriction_start}: {datetime.fromtimestamp(restriction_start)}')
        # Log.debug(f'NOW: {now}: {datetime.fromtimestamp(now)}')
        # Log.debug(f'END: {restriction_end}: {datetime.fromtimestamp(restriction_end)}')
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
    def _calculate_times(self):
        restriction_start, restriction_length, offset = self._load_restriction()

        now = fast_time() + offset
        c_d = [int(i) for i in System.date(now)]  # current date
        r_start = [int(i) for i in restriction_start.split(':')]

        restriction_start = datetime(*c_d[:2], *r_start[:1]).timestamp()
        restriction_end = restriction_start + restriction_length

        if (self.is_active):
            restriction_end = load_configuration('ip_proxy_timer')['end']

        else:
            self._write_end_time(restriction_end)

        return restriction_start, restriction_end, now

    # Calculating the time.time() of when timer should end. calculated by current days start time (time since epoch)
    # and then adding seconds of user configured amount to start time.
    def _write_end_time(self, restriction_end):
        with ConfigurationManager('ip_proxy_timer') as dnx:
            time_restriction = dnx.load_configuration()

            time_restriction['end'] = restriction_end

            dnx.write_configuration(time_restriction.expanded_user_data)

    def _load_restriction(self):
        ip_proxy = load_configuration('ip_proxy')
        logging = load_configuration('logging_client')

        restriction_start  = ip_proxy['time_restriction->start']
        restriction_length = ip_proxy['time_restriction->length']

        os_direction = logging['time_offset->direction']
        os_amount    = logging['time_offset->amount']

        offset = int(f'{os_direction}{os_amount}') * ONE_DAY

        return restriction_start, restriction_length, offset

    def _set_restriction_status(self, active):
        self.__class__._active = active

        with ConfigurationManager('ip_proxy_timer') as dnx:
            time_restriction = dnx.load_configuration()

            time_restriction['active'] = active

            dnx.write_configuration(time_restriction.expanded_user_data)
