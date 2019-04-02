#!/usr/bin/python3

import sqlite3
import os
import time
import datetime

class DBConnector:
    def __init__(self, table):
        self.table = table
        self.path = os.environ['HOME_DIR']
        
        self.db = '{}/data/dnxfwallproxy.db'.format(self.path)
        
        try:
            if not os.path.isfile (self.db):
                with open(self.db, 'w+'):
                    pass       
        except Exception:
            pass
            
    def Connect(self):
        self.conn = sqlite3.connect(self.db)
        self.conn.row_factory = sqlite3.Row
        self.c = self.conn.cursor()
        if (self.table == 'ProxyBlocks'):
            self.c.execute('create table if not exists {} (Domain, Category, Count, Reason, LastSeen)'.format(self.table))
        elif (self.table == 'PIHosts'):
            self.c.execute('create table if not exists {} (MAC, IPAddress, Domain, Reason, LastSeen)'.format(self.table))
        elif (self.table == 'FWBlocks'):
            self.c.execute('create table if not exists {} (IPSRC, IPDST, Category, Blocked, LastSeen)'.format(self.table))   

    def Disconnect(self):
        try:
            self.conn.close()
        except Exception as E: 
            print(E)
        
    def StandardInput(self, domain, cat, timestamp, reason):
        results = self.StandardEntryCheck(domain)
        if not results:
            self.c.execute('insert into {} values (?, ?, ?, ?, ?)'.format(self.table), (domain, cat, 1, reason, timestamp))
        else:
            i = results[0][2]
            t = results[0][3]
            if (timestamp - t > 10):
                i += 1
                self.c.execute('update {} set Count=?, LastSeen=?, Reason=? where Domain=?'.format(self.table), (i, timestamp, reason, domain))
                            
        self.conn.commit()

    def StandardEntryCheck(self, domain):
        self.c.execute('select * from {} where Domain=?'.format(self.table), (domain,))
        results = self.c.fetchall()
        return results

    def FWInput(self, src_ip, dst_ip, cat, timestamp, blocked):
        self.c.execute('insert into {} values (?, ?, ?, ?, ?)'.format(self.table), (src_ip, dst_ip, cat, timestamp, blocked))   

        self.conn.commit()

    def InfectedInput(self, mac, ip, domain, reason, timestamp):
        results = self.InfectedCheck(mac, domain)
        if not results:
            self.c.execute('insert into {} values (?, ?, ?, ?, ?)'.format(self.table), (mac, ip, domain, reason, timestamp))
        else:
            self.c.execute('update {} set LastSeen=? where MAC=? and Domain=?'.format(self.table), (timestamp, mac, domain))   

        self.conn.commit()
 
    def InfectedCheck(self, mac, domain):
        self.c.execute('select * from {} where MAC=? and Domain=?'.format(self.table), (mac, domain))
        results = self.c.fetchall()
        return results  

    def InfectedRemove(self, i_host, domain):
        self.c.execute('delete from PIHosts where MAC=? and Domain=?', (i_host, domain))
        self.conn.commit()                
        
    def QueryLast(self, count):
        self.c.execute('select * from {} order by LastSeen desc limit {}'.format(self.table, count))
        self.conn.row_factory = sqlite3.Row   
        results = self.c.fetchall()
#        print(results)
        return results

    def QueryTop(self, count, table='ProxyBlocks'):
        self.c.execute('select * from {} order by Count desc limit {}'.format(table, count))
        self.conn.row_factory = sqlite3.Row   
        results = self.c.fetchall()
#        print(results)
        return results

    def DomainCount(self, table='ProxyBlocks'):
        self.c.execute('select count(*) from {}'.format(table))
        self.conn.row_factory = sqlite3.Row
        results = self.c.fetchall()
      
        return results

    def RequestCount(self, table='ProxyBlocks'):
        self.c.execute('select Count from {}'.format(table))
        self.conn.row_factory = sqlite3.Row
        results = self.c.fetchall()
        
        return results
        
    def Cleaner(self):
        timestamp = int(time.time())
        month = 3600*24*30
        expire = timestamp - month
        try:
            self.c.execute('delete from {} where LastSeen < {}'.format(self.table, expire))
            self.conn.commit()
        except Exception as E:
            print(E)

if __name__ == '__main__':
#    url = 'fbob.com'
    table = 'ProxyBlocks'
#    table = 'PIHosts'
#    table = 'FWBlocks'
    ProxyDB = DBConnector(table)
    ProxyDB.Connect()
    try:
        while True:
            timestamp = int(time.time())
    #        timestamp = 11
            cat = 'douchey'
            reason = 'standard'
            url = input('list test url: ' )
            if url == '75.275.199.27':
                ProxyDB.TORInput('192.168.83.23', url, 'Entry', timestamp, True)
            elif url == 'mali.com':
                cat = 'mali'
                table = 'PIHosts'
                ProxyDB.InfectedInput('aa:aa:aa:aa:aa:aa', '192.168.10.2', url, cat, timestamp)
            elif url == 'tor':
                results = ProxyDB.QueryLast(10)
                for result in results:       
                    print(result[0],result[1],result[2],result[3], result[4])
            elif url == 'infected':
                results = ProxyDB.QueryLast(10)
                for result in results:       
                    print(result[0],result[1],result[2],result[3], result[4])
            elif url == 'top10':
                results = ProxyDB.QueryLast(10)
                for result in results:            
                    print(result[0],result[1],result[2],result[3])
            elif url == 'clean':
                ProxyDB.Cleaner(table)
            else:
                ProxyDB.StandardInput(url, cat, timestamp, reason)
    except KeyboardInterrupt:
        ProxyDB.Disconnect()


