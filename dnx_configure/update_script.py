#!/usr/bin/env python3

import os, sys

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_database.ddb_connector_sqlite import DBConnector


class UpdateScript:
    def run(self):
        pass

        # with DBConnector() as FirewallDB:
        #     FirewallDB.c.execute('drop table dnsproxy')
        #     FirewallDB.c.close()
        #     FirewallDB.conn.commit()
