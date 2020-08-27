#!/usr/bin/python3

# A minimal SQLite shell for experiments | https://docs.python.org/3.8/library/sqlite3.html

import os, sys
import time
import sqlite3
import traceback

HOME_DIR = os.environ['HOME_DIR']

conn = sqlite3.connect(f'{HOME_DIR}/dnx_system/data/dnxfirewall.sqlite3')
cur = conn.cursor()

print('Enter your SQL commands to execute in sqlite3.')
print('Enter a blank line to exit.')
print('-'*36)

def sqlite_shell():
    buffer = ''
    while True:
        line = input(': ')
        if not line:
            break

        buffer += line
        if not sqlite3.complete_statement(buffer):
            continue

        try:
            buffer = buffer.strip()
            cur.execute(buffer)

            if buffer.lstrip().upper().startswith('SELECT'):
                print(cur.fetchall())

        except sqlite3.Error as e:
            print('An error occurred: ', e.args[0])

        buffer = ''

try:
    sqlite_shell()
except KeyboardInterrupt:
    print('exiting without commit...')
else:
    print('exiting with commit...')
    conn.commit()

conn.close()