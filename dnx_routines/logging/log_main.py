#!/usr/bin/env python3

from __future__ import annotations

import os
import threading

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.standard_tools import looper, Initialize
from dnx_gentools.file_operations import load_configuration, cfg_read_poller

from dnx_routines.database.ddb_connector_sqlite import DBConnector
from dnx_routines.configure.system_info import System

from dnx_routines.logging.log_client import Log

__all__ = (
    'LogService',
)

LOG_NAME = 'system'

EXCLUDED_MODULES = ['combined', 'syslog']

_system_date = System.date
_format_time = System.format_time


class LogService:
    _log_modules: ClassVar[list[str]] = [
            x for x in os.listdir(f'{HOME_DIR}/dnx_system/log') if x not in EXCLUDED_MODULES
        ]

    __slots__ = (
        'log_length', 'log_level', '_initialize'
    )

    @classmethod
    def run(cls):
        self = cls()

        self.organize()

    def __init__(self) -> None:
        self._initialize = Initialize(Log, 'LogService')

        self.log_length: int = 999
        self.log_level:  int = -1

        threading.Thread(target=self.get_settings).start()

        self._initialize.wait_for_threads(count=1)

        threading.Thread(target=self.clean_db_tables).start()
        threading.Thread(target=self.clean_blocked_table).start()

    @looper(THREE_MIN)
    def organize(self) -> None:
        log_entries = []

        date = str_join(_system_date())
        for module in self._log_modules:

            log_entries.extend(self._pull_recent_logs(module, date))

        if (not log_entries):
            return

        with open(f'{HOME_DIR}/dnx_system/log/combined/{date}-combined.log', 'w+') as system_log:
            system_log.write('\n'.join(sorted(log_entries)))

        del log_entries  # to reclaim system memory

    @staticmethod
    def _pull_recent_logs(module: str, date: str) -> list[str]:
        log_path = f'{HOME_DIR}/dnx_system/log/{module}/{date}-{module}.log'

        if not os.path.isfile(log_path):
            return []

        with open(log_path, 'r') as log_file:
            return [x.strip() for x in log_file.readlines(2048)[:20]]

    @looper(ONE_DAY)
    def clean_db_tables(self) -> None:
        with DBConnector(Log) as FirewallDB:
            for table in ['dnsproxy', 'ipproxy', 'ips', 'infectedclients']:
                FirewallDB.table_cleaner(self.log_length, table=table)

        # NOTE: consider moving this into the DBConnector, so it can report if no exc are raised.
        Log.notice('completed daily database cleaning')

    @looper(THREE_MIN)
    def clean_blocked_table(self) -> None:
        with DBConnector(Log) as FirewallDB:
            FirewallDB.blocked_cleaner(table='blocked')

        # NOTE: consider moving this into the DBConnector, so it can report if no exc are raised.
        Log.debug('completed blocked database cleaning')

    @cfg_read_poller('logging_client')
    def get_settings(self, cfg_file: str) -> None:
        log_settings = load_configuration(cfg_file)

        self.log_length = log_settings['logging->length']
        self.log_level = log_settings['logging->level']

        self._initialize.done()

def run():
    LogService.run()


if (INIT_MODULE == LOG_NAME):
    Log.run(name=LOG_NAME)
