#!/usr/bin/python3

# A minimal SQLite shell for experiments | https://docs.python.org/3.8/library/sqlite3.html

import sqlite3

from dnx_gentools.def_constants import HOME_DIR

valid_commands = set(['select',])

conn = sqlite3.connect(f'{HOME_DIR}/dnx_system/data/dnxfirewall.sqlite3')
cur = conn.cursor()

print('Enter your SQL commands to execute in sqlite3.')
print('Enter a blank line to exit.')
print('-'*36)

def sqlite_shell():

    while True:

        # set to reset buffer after each line. (no multi-line commands)
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