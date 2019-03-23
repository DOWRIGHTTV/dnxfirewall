#!/usr/bin/python3

import sqlite3
import os
import time
import datetime

class DBConnector:
    def __init__(self):
        self.path = os.environ['HOME_DIR']
        self.db = '{}/data/dnxfwallproxy.db'.format(self.path)
        self.table = 'PROXYBLOCKS'
        
        try:        
            if not os.path.isfile (self.db):
                with open(self.db, 'w+') as db:
                    pass       
        except Exception:
            pass
            
    def Connect(self):
        self.conn = sqlite3.connect(self.db)
        self.conn.row_factory = sqlite3.Row
        self.c = self.conn.cursor()
        self.c.execute('create table if not exists {} (URL, Category, Count, LastHit)'.format(self.table))
     
    def Disconnect(self):
        try:
            self.conn.close()
        except Exception as E:
            print(E)
        
    def Input(self, url, cat, timestamp, db='PROXYBLOCKS'):
        results = self.EntryCheck(url)
        print('INPUT RESULTS: {}'.format(results))
        if not results:
            self.c.execute('insert into {} values (?, ?, ?, ?)'.format(db), (url, cat, 1, timestamp))
        else:
            i = results[0][2]
            i += 1
            self.c.execute('update {} set Count=?, LastHit=? where URL=?'.format(db), (i, timestamp, url))
        self.conn.commit()
                
    def EntryCheck(self, url, db='PROXYBLOCKS'):
        self.c.execute('select * from {} where URL=?'.format(db), (url,))
        results = self.c.fetchall()
        return results
        
    def QueryLast(self, count, db='PROXYBLOCKS'):
        self.c.execute('select * from {} order by LastHit desc limit {}'.format(db, count))
        self.conn.row_factory = sqlite3.Row   
        results = self.c.fetchall()
        print(results)
        return results
        
        
    def Cleaner(self, db='PROXYBLOCKS'):
        timestamp = int(time.time())
        month = 3600*24*30       
        expire = timestamp - month                
        try:
#            self.c.execute('select * from {} where LastHit < {}'.format(db, expire))
#            LOL = self.c.fetchall()
#            print(LOL)
            self.c.execute('delete from {} where LastHit < {}'.format(db, expire))
            self.conn.commit()
        except Exception as E:
            print(E)

if __name__ == '__main__':
#    url = 'fbob.com'
    ProxyDB = DBConnector()
    ProxyDB.Connect()
    try:
        while True:
            timestamp = int(time.time())
    #        timestamp = 11
            cat = 'douchey'
            url = input('list test url:' )
            if url == 'top10':
                results = ProxyDB.QueryLast(10)
                for result in results:            
                    print(result[0],result[1],result[2],result[3],)
            elif url == 'clean':
                ProxyDB.Cleaner()       
            else:
                ProxyDB.Input(url, cat, timestamp)
    except KeyboardInterrupt:
        ProxyDB.Disconnect()


