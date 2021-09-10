#!/usr/bin/env python3

from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
import os, sys
import json
import threading

from subprocess import check_output

HOME_DIR = os.environ.get('HOME_DIR', os.path.realpath('..'))
sys.path.insert(0, HOME_DIR)

from dnx_sysmods.configure.def_constants import SHELL_SPACE
from dnx_shell.dnx_shell_main import TopLevel
from dnx_shell.dnx_shell_authentication import Authentication


class DNXShell:
    def __init__(self):
        self.HOST = ''
        self.PORT = 6912

    def Start(self):
        self.Server()
        try:
            self.Main()
        except KeyboardInterrupt:
            self.s.close()
            os._exit(0)

    def Server(self):
        #Bind socket to local host and port
        self.s = socket(AF_INET, SOCK_STREAM)
        self.s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.s.bind((self.HOST, self.PORT))

        #Start listening on socket
        self.s.listen(3)

    def Shell(self, conn):
        while True:
            #calling Top Level command handler class. this keep the main server logic clean and only has to deal with
            # connections and authentication.
            result = TopLevel(conn).CommandLoop()
            if (result == 'QUIT'):
                return 'QUIT'

    def Main(self):
        while True:
            #Waiting for a connection
            conn, addr = self.s.accept()
            print('Connected with ' + addr[0] + ':' + str(addr[1]))

            #Sending connection to a thread
            threading.Thread(target=self.Authenticate, args=(conn,)).start()

    #Authenticing the connection
    def Authenticate(self, conn):
        Account = Authentication()
        i = 0
        authenticated = False
        while True:
            conn.send('username: '.encode('utf-8'))
            username = conn.recv(1024).decode().strip('\r\n')
            while True:
                conn.send('password: '.encode('utf-8'))
                password = conn.recv(1024).decode().strip('\r\n')

                if (not authenticated and i < 3):
                    authenticated = Account.Login(username, password)
                    if (authenticated):
                        break

                    i += 1

                else:
                    conn.send('authentication not successful. Disconnecting.\r\n'.encode('utf-8'))
                    conn.close()
                    break

            conn.send('Authenticated\r\n'.encode('utf-8'))
            result = self.Shell(conn)
            if (result == 'QUIT'):
                conn.close()
                break

if __name__ == '__main__':
    DNX = DNXShell()
    DNX.Start()
