#!/usr/bin/python3

# A minimal SQLite shell for experiments | https://docs.python.org/3.8/library/sqlite3.html

import os, sys
import time
import sqlite3
import traceback

HOME_DIR = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-2]))

valid_commands = set(['select',])

conn = sqlite3.connect(f'{HOME_DIR}/dnx_system/data/dnxfirewall.sqlite3')
cur = conn.cursor()

print('Enter your SQL commands to execute in sqlite3.')
print('Enter a blank line to exit.')
print('-'*36)

def sqlite_shell():

    while True:
        line, buffer = input(': '), ''
        if (not line):
            break

        buffer += line.strip()
        if (not sqlite3.complete_statement(buffer) or
                buffer.split()[0] not in valid_commands):
            continue

        try:
            cur.execute(buffer.strip())
        except sqlite3.Error as e:
            print('An error occurred: ', e.args[0])

        else:
            print(cur.fetchall())

try:
    sqlite_shell()
except KeyboardInterrupt:
    print('exiting without commit...')

else:
    print('exiting with commit...')
    conn.commit()

conn.close()