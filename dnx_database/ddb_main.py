#!/usr/bin/env python3

import os, sys
import time
import json
import threading
import traceback

from socket import socket, AF_INET, SOCK_DGRAM
from collections import deque

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_namedtuples as dnx_nt

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_standard_tools import dnx_queue, looper
from dnx_database.ddb_connector import DBConnector


class DatabaseService:

    def start(self):
        self._create_service_socket()

        threading.Thread(target=self._receive_database_socket).start()

        self._service_loop()

    # main service loop to remove the recursive callback of queue handler.
    def _service_loop(self):
        print('[+] Starting database log entry processing queue.')
        fail_count = 0
        while True:
            with DBConnector() as database:
                self._write_to_database(database) # pylint: disable = no-value-for-parameter

            fail_count += 1
            if (not fail_count % 5):
                # TODO: log this as critical or something
                pass

            time.sleep(ONE_SEC)

    @dnx_queue(None, name='Database')
    def _write_to_database(self, database, job):
        method, timestamp, log_info = job

        method = getattr(database, f'{method}_input')
        method(timestamp, log_info)

        # NOTE: this might be wasteful
        database.commit_entries()

    @looper(NO_DELAY)
    def _receive_database_socket(self):
        try:
            data = self._service_socket.recv(2048)
        except OSError:
            traceback.print_exc()
        else:
            data = json.loads(data.decode())

            name = data['method']
            # NOTE: this is grabbing correct namedtuple, maybe locally store again?
            log_tuple = getattr(dnx_nt, f'{name}_log'.upper())
            log_entry = log_tuple(*data['log'])

            self._write_to_database.add((name, data['timestamp'], log_entry)) # pylint: disable = no-member
            print('ADDED LOG TO QUEUE!')

    def _create_service_socket(self):
        self._service_socket = socket(AF_INET, SOCK_DGRAM)
        self._service_socket.bind((f'{LOCALHOST}', DATABASE_SOCKET))

if __name__ == '__main__':
    DBService = DatabaseService()
    DBService.start()
