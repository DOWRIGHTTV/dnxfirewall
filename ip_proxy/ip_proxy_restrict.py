#!/usr/bin/env python3

import os, sys
import time
import json
import threading

from datetime import datetime

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_configure.dnx_file_operations import load_configuration, cfg_read_poller, ConfigurationManager
from dnx_configure.dnx_configure import System
from dnx_iptools.dnx_standard_tools import looper, classproperty, Initialize

from ip_proxy.ip_proxy_log import Log


class LanRestrict:
    '''lan restriction management is done within this class.

    public attributes: is_enabled, is_active

    call run method to start service.

    '''
    _enabled = False
    _active  = False

    def __init__(self, name):
        self.initialize = Initialize(Log, name)

    @classproperty
    def is_enabled(cls): # pylint: disable=no-self-argument
        return cls._enabled

    @classproperty
    def is_active(cls): # pylint: disable=no-self-argument
        return cls._active

    @classmethod
    def run(cls, IPProxy):
        '''initializes settings and attributes then runs timer service in a new thread before returning.'''
        self = cls(IPProxy.__name__)
        self.IPProxy = IPProxy

        cls.__load_status()

        threading.Thread(target=self._get_settings).start()
        threading.Thread(target=self._tracker).start()

        self.initialize.wait_for_threads(count=2)

    @cfg_read_poller('ip_proxy')
    def _get_settings(self, cfg_file):
        restriction_settings = load_configuration(cfg_file)

        enabled = restriction_settings['ip_proxy']['time_restriction']['enabled']
        self._change_attribute('_enabled', enabled)

        self.initialize.done()

    @looper(ONE_MIN)
    def _tracker(self):
        restriction_start, restriction_end, now = self._calculate_times()

        Log.debug(f'ENABLED: {self.is_enabled} | ACTIVE: {self.is_active}')
        Log.debug(f'START: {restriction_start}: {datetime.fromtimestamp(restriction_start)}')
        Log.debug(f'NOW: {now}: {datetime.fromtimestamp(now)}')
        Log.debug(f'END: {restriction_end}: {datetime.fromtimestamp(restriction_end)}')
        if (not self.is_enabled and self.is_active):
            self._set_restriction_status(active=False)

        # NOTE: validate end check is doing anything. if not remove it to make code easier to deal with
        elif (self.is_enabled and not self.is_active
                and restriction_start < now < restriction_end):
            self._set_restriction_status(active=True)

            Log.notice('LAN Time Restriction in effect.')

        elif (self.is_active and now > restriction_end):
            self._set_restriction_status(active=False)

            Log.notice('LAN Time Restriction released.')

        self.initialize.done()

    # Calculating what the current date and time is and what the current days start time is in epoch
    # this must be calculated daily as the start time epoch is always changing
    def _calculate_times(self):
        restriction_start, restriction_length, offset = self._load_restriction()

        now = time.time() + offset
        c_d = [int(i) for i in System.date(now)] # current date

        restriction_start = restriction_start.split(':')
        restriction_start = [int(i) for i in restriction_start]

        restriction_start = datetime(c_d[0], c_d[1], c_d[2], restriction_start[0], restriction_start[1]).timestamp()
        restriction_start = restriction_start
        restriction_end = restriction_start + restriction_length

        if (self.is_active):
            restriction_status = load_configuration('ip_proxy_timer.json')
            restriction_end = restriction_status['time_restriction']['end']
        else:
            self._write_end_time(restriction_end)

        return restriction_start, restriction_end, now

    # Calculating the time.time() of when timer should end. calculated by current days start time (time since epoch)
    # and then adding seconds of user configured amount to start time.
    def _write_end_time(self, restriction_end):
        with ConfigurationManager('ip_proxy_timer.json') as dnx:
            time_restriction = dnx.load_configuration()

            time_restriction['time_restriction'].update({'end': restriction_end})

            dnx.write_configuration(time_restriction)

    def _load_restriction(self):
        restriction = load_configuration('ip_proxy.json')
        offset_settings = load_configuration('logging_client.json')

        restriction_start  = restriction['ip_proxy']['time_restriction']['start']
        restriction_length = restriction['ip_proxy']['time_restriction']['length']

        offset = offset_settings['logging']['time_offset']
        os_direction = offset['direction']
        os_amount    = offset['amount']

        offset = int(f'{os_direction}{os_amount}') * 3600

        return restriction_start, restriction_length, offset

    def _set_restriction_status(self, active):
        self._change_attribute('_active', active)
        with ConfigurationManager('ip_proxy_timer') as dnx:
            restriction_status = dnx.load_configuration()

            restriction_status['time_restriction']['active'] = active

            dnx.write_configuration(restriction_status)

    @classmethod
    def __load_status(cls):
        time_restriction = load_configuration('ip_proxy_timer')

        cls._active = time_restriction['time_restriction']['active']

    @classmethod
    def _change_attribute(cls, name, status):
        setattr(cls, name, status)
