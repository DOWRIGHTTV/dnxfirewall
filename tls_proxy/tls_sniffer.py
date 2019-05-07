#!/usr/bin/env python3

from socket import socket, inet_aton, inet_ntoa, AF_PACKET, SOCK_RAW
import struct
import threading
import binascii
import codecs
import time

class SSLHandlerThread:
    ''' This class is called from the main Sniffer class in the event that a Client Hello is detected.
    This class will start tracking the SSL/TLS handshake based on the information given to it from the 
    Main Sniffer regarding the Client Hello. This class will have access to the socket of the Sniffer
    directly and will call the Header Parse class to determine whether it is apart of the initial handshake.
    This will keep each handshake in its own thread for persistent tracking until it completes. After the
    SSL Server Hello packet is combined up until the Server Hello end it will send the reorder and reformat
    the packet to look as though it was sent as one, then will send the packet to the SSL Parse class to have
    the SSL Cert in the chain split from the packet and sent to the TLS Proxy. '''
    def __init__(self, connection, tcp_info, action):
        self.connection = connection
        seq_number, ack_number, _, tcp_segment_length = tcp_info
        self.action = action
        self.active = True

        self.tcp_header_length = 0

        self.ack_offset = ack_number
        self.expected_ack_number = seq_number + tcp_segment_length
        
        self.sequence_offset = 0
        self.initial_sequence_number = ack_number
        self.expected_sequence_number = ack_number
        self.valid_sequence = set()

        self.ssl_packet_validation = {}
        self.ssl_packet = {}

        self.handshake = {'server_hello': {
                            'status': False },
                        'hello_done': {
                            'status': False }
                        }

    ''' SSL Handler Thread Logic contained, ensures packets are part of same SSL Handshake,
    Adds packets to a dictionary with sequence number and contents as key/value pair, then 
    will send packets for reorder, header removal, and rejoin to then be sent to SSL Certificate 
    Parser prior to being sent back to the proxy '''
    def Start(self, data):
        server_hello = self.handshake['server_hello']
        hello_done = self.handshake['hello_done']
        start = time.time()
        print('+'*30)
        same_packet = False
        ack_number = None
        forward = True
        try:
            SSLT = SSLType(data)
            _, tcp_info = SSLT.Parse()
            if (tcp_info):
                seq_number, ack_number, tcp_header_length, tcp_segment_length = tcp_info
                
            if (ack_number == self.expected_ack_number):
                print(f'ACK: {ack_number} || EXCPECTED ACK: {self.expected_ack_number}')
                if (seq_number in self.ssl_packet):
                    marked = False
                elif (seq_number == self.initial_sequence_number):
                    print(f'SEQ: {seq_number} || INITIAL SEQUENCE: {self.initial_sequence_number}')
                    self.tcp_header_length = tcp_header_length
                    server_hello.update({'status': True}) #, 'sequence': seq_number, 'segment': tcp_segment_length})
                    marked = True
                    same_packet = True

                elif (seq_number == self.expected_sequence_number):                       
                    print(f'SEQ: {seq_number} || EXPECTED SEQUENCE: {self.expected_sequence_number}')
                    marked = True

                else:
                    print(f'OUT OF ORDER PACKET || SEQ {seq_number} || EXPECTED SEQUENCE: {self.expected_sequence_number}')
                    marked = True

                if (marked):
                    self.ssl_packet_validation[seq_number] = tcp_segment_length
                    self.expected_sequence_number += tcp_segment_length
                    self.ssl_packet[seq_number] = data

                ''' Identified finished packet, calling method to reorder and remove headers. '''
                if (self.ssl_packet[seq_number][-4:] == b'\x0e\x00\x00\x00'):
                    hello_done.update({'status': True})
                    print('DETECTED HELLO DONE')
                
                ''' Initial condition to ensure that the first and last packet has been received as part of the SSL
                handshake. Logic around determining if there is more that 3 parts is still iffy. A local counter is 
                checked if start/end is detected to see if they are part of the same packet which will mark as complete. '''
                if (server_hello['status'] and hello_done['status']):
                    complete = False
                    ('HAVE SERVER H AND H DONE')
                    if (len(self.ssl_packet) in {1} and same_packet):
                        print('SHORT ASS SSL PACKET')
                        complete = True
                    else:
                        seq_validation = 0
                        packet_validation = sorted(self.ssl_packet_validation.items())
                        for i, (sequence, length) in enumerate(packet_validation, 1):
                            if i in {1}:
                                pass
                            elif (sequence != seq_validation):
                                break
                            seq_validation = sequence + length
                        else:
                            print('COMPLETE PACKET.')
                            complete = True
                            
                    if (complete):
                        print('='*30)
                        ssl_packet = self.FixPacketFormat()
                        ssl = SSL(ssl_packet, tcp_header_length)
                        ssl.Start()

                        end = time.time()
                        print('*'*50)
                        print(end-start)
                        print('*'*50)
                        if (ssl.certificate_chain):
                            self.action(self.connection, ssl)

                return forward
            else:
                return True
        except Exception as E:
            print(E)
       
    ''' Getting ascending order of sequence numbers, iterating over packets in order, removing the
    packet headers || Ethernent, IP, TCP || and combining to complete full server hello message '''
    def FixPacketFormat(self):
        ssl_packet_order = sorted(self.ssl_packet.keys())
        header_remove = 34 + self.tcp_header_length

        # for seq_number in ssl_packet_order:
        #     print(seq_number)
        #     print(self.ssl_packet[seq_number])

        ssl_packet = b''
        for seq_number in ssl_packet_order:
            packet = self.ssl_packet[seq_number]
            if (seq_number == self.initial_sequence_number):
                ssl_packet += packet
            else:                
                ssl_packet += packet[header_remove:]
        
#        print(ssl_packet)
        return ssl_packet

    ''' Timeing out Thread after 750 MS to ensure threads do not remain up for invalid or missed traffic '''
    def Timer(self):
        time.sleep(.750)
        self.active = False
                                        
class SSLType:
    ''' Class to parse packet header information, including the ssl handshake protocol. All other payloads
    will be ignored. This class isntance will be sent back to the TLS Proxy where it will be able to access all
    class variabled set while parsing to be used for logging purposes or to whitelist/blacklist based on ip or port '''
    def __init__(self, data):
        self.data = data

    def Parse(self):
        hs_type = None
        tcp_info = self.TCP()
        self.HandshakeProtocol()
        if (self.content_type in {22} and self.handshake_type in {1}):
            hs_type = 1
        elif (self.content_type in {22} and self.handshake_type in {2}):
            hs_type = 2
                            
        return hs_type, tcp_info

    ''' Parsing TCP information like sequence and acknowledgement number amd calculated tcp header
    length to be used by other classes for offset/proper indexing of packet contents.
    Returning all relevant information back to HeaderParse Start method to be redistributed to other classes
    based on need '''
    def TCP(self):
        tcp_header_length = 0
        bit_values = [32,16,8,4]

        tcp = self.data[34:66]
        seq_number = tcp[4:8]
        ack_number = tcp [8:12]
        seq_number = struct.unpack('!L', seq_number)[0]
        ack_number = struct.unpack('!L', ack_number)[0]
        tmp_length = bin(tcp[12])[2:6]

        for i, bit in enumerate(tmp_length):
            if (bit == '1'):
                tcp_header_length += bit_values[i]

        tcp_segment_length = len(self.data) - 34
        tcp_segment_length -= tcp_header_length

        return [seq_number, ack_number, tcp_header_length, tcp_segment_length]

    ''' Parsing SSL Handshake Protocol Types, looking for Type 1 (Client Hello) to start handshake tracking, then
    looking for Type 2 (Server Hello). Handshake Type logical handling is done outside of this method '''
    def HandshakeProtocol(self):
        handshake_protocol = struct.unpack('!B2H2BH', self.data[66:75])
        self.content_type = handshake_protocol[0]
        self.handshake_type = handshake_protocol[3]

class SSL:
    ''' This class is to being dealign with the ssl/tls portion of the packet. The entire packet will be looked
    for the first time since prior to this class the packet was split amongth multiple tcp packets. Though the entire
    packet is accessable, all header information will not need to be looked at again due to it already having to be
    parsed to track the connections. This class will be sent into the TLS Proxy where each class object will be accessible
    for further review. As of right now, no additional parsing is being done in this module after this point. Depending on
    how the Proxy side works, additional logic may need to be added here to pinpoint specific variables within the certs
    instead of giving the Proxy the separated certs in their entirety. '''
    def __init__(self, data, tcp_size):
        self.data = data
        self.tcp_size = tcp_size

        self.offset = 0
        self.certificate_offset = 0
        self.certs_combined = 0
        
        self.certificate_chain = []
        self.Parsing = True

    ''' Starting the parsing of the entire packet, focusing on the ssl certificates contained in the packet
    will identify all certificates and append it to a certificate chain list to be more specifilly parsed
    if possible. '''
    def Start(self):
        ''' Calling a recursive method until the certificate handshake protocol type is found which will match
        on type 11, type 2 will apply an offset and pass, all else will be ignored. '''
        while self.Parsing:
            self.HandshakeProtocol()
            if (self.handshake_type == 11):
                self.AllCertificates()
                ''' Calling a recursive method to parse each individual certificate and then checking against total
                expected length. Will set intitial while look condition to False and will break. This will complete
                the certificate chain collection process. '''
                while True:                       
                    self.Certificate_Chain()
                    print(f'CERTS COMBINED {self.certs_combined} : CERTS TOTAL LENGTH {self.certificates_total_length}')
                    if (self.certs_combined == self.certificates_total_length):
                        self.Parsing = False
                        break                  
            elif (self.handshake_type == 2):
                self.offset += self.handshake_type_length + 4 + 5
            else:
                break
    
    ''' Checking the Handshake Protocol Type || 2 (Server Hello), 11 (Certificate) || if Server Hello, implements offset
    to allow for the Certificate to index correctly. If already type 11 (Certificate), then no offset will be applied
    upon returning from this method. '''
    def HandshakeProtocol(self):
        handshake_protocol = struct.unpack('!B2H2BH', self.data[self.offset + 66:self.offset + 75])
        self.content_type = handshake_protocol[0]
        self.version = handshake_protocol[1]
        self.handshake_content_length = handshake_protocol[2]
        self.handshake_type = handshake_protocol[3]
        self.handshake_type_length = handshake_protocol[5]
        
    ''' Parsing the initial certificates fields which contains total length of all certificates which will be used to validate the parsing is complete
    and will also help with indexing the first certificate start location. ''' 
    def AllCertificates(self):
        certificates_length_start = self.offset + self.tcp_size + 34 + 9
        self.certificates_total_length = struct.unpack('!H', self.data[certificates_length_start + 1:certificates_length_start + 3])[0]
        
        certificates_start = certificates_length_start + 3
        self.certificates = self.data[certificates_start:certificates_start+self.certificates_total_length]     

    ''' Checking each individual certificate for the start and end, appending it to a chain list, and setting the certificate offset
    as the length of the current certificate to ensure the next certificate start is indexed correctly '''
    def Certificate_Chain(self):
        certificate_length = struct.unpack('!H', self.certificates[self.certificate_offset+1:self.certificate_offset+3])[0]        
        certificate = self.certificates[self.certificate_offset + 3:self.certificate_offset+certificate_length + 3]                 

        self.certificate_offset += certificate_length + 3        
        self.certs_combined += certificate_length + 3

        self.certificate_chain.append(certificate)
