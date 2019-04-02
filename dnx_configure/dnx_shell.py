#!/usr/bin/python3

from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
import os, sys
import threading

from subprocess import check_output

class DOWServer:
    def __init__(self):
        self.HOST = ''
        self.PORT = 6912

        self.users = {'dowright': 'password'}

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
            conn.send('dow$> '.encode('utf-8'))
            data = conn.recv(1024).decode().strip('\r\n')

            result = self.Parse(data, conn)
            if (result == 'QUIT'):
                conn.close()
                break

    def Main(self):
        while True:
            #Waiting for a connection
            conn, addr = self.s.accept()
            print('Connected with ' + addr[0] + ':' + str(addr[1]))

            #Sending connection to a thread
            threading.Thread(target=self.Authenticate, args=(conn,)).start()


    #Authenticing the connection
    def Authenticate(self, conn):
        i = 0
        authenticated = False
        while True:
            conn.send('username: '.encode('utf-8'))
            username = conn.recv(1024).decode().strip('\r\n')
            conn.send('password: '.encode('utf-8'))
            password = conn.recv(1024).decode().strip('\r\n')

            if (not authenticated and i < 3):
                authenticated = self.CheckUser(username, password)
                i += 1
                if (authenticated):
                    break
            else:
                conn.send('authentication not successful. Disconnecting.\r\n'.encode('utf-8'))
                conn.close()
                break

        conn.send('Authenticated\r\n'.encode('utf-8'))
        self.Shell(conn)

    #validating credentials
    def CheckUser(self, username, password):
        if username in self.users:
            if (self.users[username] == password):
                return True
            else: 
                return False


    def Parse(self, data, conn):
        if (data == 'quit'):
            return 'QUIT'
        elif (data == 'version'):
            conn.send('dow$> '.encode('utf-8'))
            conn.send('DOW 0.9\n'.encode('utf-8'))

DOW = DOWServer()
DOW.Start()