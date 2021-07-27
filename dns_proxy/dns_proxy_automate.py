#!/usr/bin/env python3

import os, sys
import time
import threading
import socket
import ssl

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

import dnx_configure.dnx_signature_operations as signature_operations

from dnx_configure.dnx_constants import * # pylint: disable=unused-wildcard-import
from dnx_configure.dnx_file_operations import * # pylint: disable=unused-wildcard-import
from dnx_iptools.dnx_protocol_tools import create_dns_query_header, convert_string_to_bitmap
from dnx_iptools.dnx_standard_tools import dynamic_looper, Initialize

from dns_proxy.dns_proxy_log import Log


class Configuration:
    _proxy_setup  = False
    _server_setup = False
    _keywords = []

    __slots__ = (
        # callbacks
        'DNSProxy', 'DNSServer', 'DNSCache',

        # protected vars
        '_initialize',
    )

    def __init__(self, name):
        self._initialize = Initialize(Log, name)

        # this is setting the reference for the entire process/module since it is stored as a class variable.
        ConfigurationManager.set_log_reference(Log)

    @classmethod
    def proxy_setup(cls, DNSProxy):
        '''start threads for tasks required by the DNS proxy. blocking until settings are loaded/initialized.'''
        if (cls._proxy_setup):
            raise RuntimeError('proxy setup should only be called once.')
        cls._proxy_setup = True

        # NOTE: might be temporary, but this needed to be moved outside of the standard/bitmap sigs since they are
        # now being handled by an external C extension (cython)
        cls._keywords = load_keywords(Log=Log)

        self = cls(DNSProxy.__name__)
        self.DNSProxy = DNSProxy

        threading.Thread(target=self._get_proxy_settings).start()
        threading.Thread(target=self._get_list, args=('whitelist',)).start()
        threading.Thread(target=self._get_list, args=('blacklist',)).start()

        self._initialize.wait_for_threads(count=3)

    @classmethod
    def server_setup(cls, DNSServer, DNSCache):
        '''start threads for tasks required by the DNS server. This will ensure all automated threads
        get started, including reachability. blocking until settings are loaded/initialized.'''
        if (cls._server_setup):
            raise RuntimeError('server setup should only be called once.')
        cls._server_setup = True

        self = cls(DNSServer.__name__)
        self.DNSServer = DNSServer
        self.DNSCache  = DNSCache

        threading.Thread(target=self._get_server_settings).start()

        self._initialize.wait_for_threads(count=1)

    @cfg_read_poller('dns_proxy')
    def _get_proxy_settings(self, cfg_file):
        dns_proxy = load_configuration(cfg_file)['dns_proxy']

        signatures = self.DNSProxy.signatures
        # CATEGORY SETTINGS
        enabled_keywords = []
        for cat, setting in dns_proxy['categories']['default'].items():
            # identifying enabled keyword search categories
            if (setting['keyword']):
                enabled_keywords.append(DNS_CAT[cat])

            # identifying enabled general categories
            if (setting['enabled']):
                signatures.en_dns.add(DNS_CAT[cat])

            # removing category if present in memory
            else:
                dns_cat = DNS_CAT[cat]
                if (dns_cat in signatures.en_dns):
                    signatures.en_dns.remove(dns_cat)

        # KEYWORD SETTINGS
        # copying keyword signature list in memory to a local object. iterating over list. if the current item
        # category is not an enabled category the signature will get removed and offset will get adjustest to
        # ensure the index stay correct.
        mem_keywords, offset = signatures.keyword.copy(), 0
        for i, signature in enumerate(mem_keywords):
            _, cat = signature
            if cat not in enabled_keywords:
                signatures.keyword.pop(i-offset)
                offset += 1

        # iterating over keywords from the signature set. if the keyword category is enabled and the current
        # signature is not already in memory it will be added.
        for signature, cat in self._keywords:
            if cat in enabled_keywords and signature not in signatures.keyword:
                signatures.keyword.append((signature, cat))

        # TLD SETTINGS | generator
        for tld, setting in load_tlds():
            signatures.tld[tld] = setting

        self._initialize.done()

    @cfg_read_poller('dns_server')
    def _get_server_settings(self, cfg_file):
        DNSServer = self.DNSServer

        dns_settings = load_configuration(cfg_file)['dns_server']

        dns_servers = dns_settings['resolvers']
        tls_enabled  = dns_settings['tls']['enabled']
        DNSServer.udp_fallback = dns_settings['tls']['fallback']

        DNSServer.protocol = PROTO.DNS_TLS if tls_enabled else PROTO.UDP

        names = ['primary', 'secondary']
        for name, cfg_server, mem_server in zip(names, dns_servers.values(), DNSServer.dns_servers):

            if (cfg_server['ip_address'] != mem_server['ip']):

                getattr(DNSServer.dns_servers, name).update({
                    'ip': dns_servers[name]['ip_address'],
                    PROTO.UDP: True, PROTO.DNS_TLS: True
                })

        DNSServer.dns_records = dns_settings['records']

        # CLEAR DNS or TOP Domains cache
        self.DNSCache.clear_dns_cache   = dns_settings['cache']['standard']
        self.DNSCache.clear_top_domains = dns_settings['cache']['top_domains']

        self._initialize.done()

    @cfg_write_poller
    # handles updating user defined signatures in memory/propogated changes to disk.
    def _get_list(self, lname, cfg_file, last_modified_time):
        timeout_detected = self._check_for_timeout(lname)
        memory_list = getattr(self.DNSProxy, lname).dns
        # if a rule timeout is detected for an entry in memory. we will update the config file
        # to align with active rules, then we will remove the rules from memory.
        if (timeout_detected):
            loaded_list = self._update_list_file(lname, cfg_file)

            self._modify_memory(memory_list, loaded_list, action=CFG.DEL)

        # if file has been modified the modified list will be referenced to make in place changes to memory
        # list, specifically around adding new rules and the new modified time will be returned. if not modified,
        # the last modified time is returned and not changes are made.
        try:
            modified_time = os.stat(f'{HOME_DIR}/dnx_system/data/usr/{cfg_file}')
        except FileNotFoundError:
            modified_time = os.stat(f'{HOME_DIR}/dnx_system/data/{cfg_file}')

        if (modified_time == last_modified_time):
            return last_modified_time

        loaded_list = load_configuration(cfg_file)[lname]['domain']

        self._modify_memory(memory_list, loaded_list, action=CFG.ADD)

        # ip whitelist specific. will do an inplace swap of all rules needing to be added or removed the memory.
        if (lname == 'whitelist'):
            self._modify_ip_whitelist(cfg_file)

        self._initialize.done()

        return modified_time

    def _modify_memory(self, memory_list, loaded_list, *, action):
        '''removing/adding signature/rule from memory as needed.'''
        if (action in [CFG.ADD, CFG.ADD_DEL]):

            # iterating over rules/signatures pulled from file
            for rule, settings in loaded_list.items():
                bitmap_key = convert_string_to_bitmap(rule, DNS_BIN_OFFSET)

                # adding rule/signature to memory if not present
                if (bitmap_key not in memory_list):
                    settings['key'] = rule
                    memory_list[bitmap_key] = settings

        if (action in [CFG.DEL, CFG.ADD_DEL]):

            # iterating over rules/signature in memory
            for rule, settings in memory_list.copy().items():
                bitmap_key = convert_string_to_bitmap(rule, DNS_BIN_OFFSET)

                # if rule is not present in config file it will be removed from memory
                if (settings['key'] not in loaded_list):
                    memory_list.pop(rule)

    def _modify_ip_whitelist(self, cfg_file):
        memory_ip_list = self.DNSProxy.whitelist.ip
        loaded_ip_list = load_configuration(cfg_file)['whitelist']['ip_whitelist']

        # iterating over ip rules in memory.
        for ip in memory_ip_list.copy():

            # if it is not in the config file it will be removed.
            if (f'{ip}' not in loaded_ip_list):
                memory_ip_list.pop(ip)

        # iterating over ip rules in configuration file
        for ip, settings in loaded_ip_list.items():
            # convert to ip address object which is the type stored as key
            ip = IPv4Address(ip)

            # if it is not in memory and the rule type is "global" it will be added
            if (ip not in memory_ip_list and settings['type'] == 'global'):
                memory_ip_list[ip] = True

    # checking corresponding list file for any time based rules timing out. will return True if timeout
    # is detected otherwise return False.
    def _check_for_timeout(self, lname):
        now = fast_time()
        for info in getattr(self.DNSProxy, lname).dns.values():
            if (now < info['expire']): continue

            return True

        return False

    # updating the file with necessary changes.
    def _update_list_file(self, lname, cfg_file):
        now = fast_time()
        with ConfigurationManager(cfg_file) as dnx:
            lists = dnx.load_configuration()

            loaded_list = lists[lname]['domain']
            for domain, info in loaded_list.copy().items():
                if (now < info['expire']): continue

                loaded_list.pop(domain, None)

            dnx.write_configuration(lists)

            return loaded_list

    @staticmethod
    def load_dns_signature_bitmap():

        # NOTE: old method of created combined signature file and loaded seperately
        signature_operations.combine_domains()

        wl_exceptions = load_configuration('whitelist')['whitelist']['exception']
        bl_exceptions = load_configuration('blacklist')['blacklist']['exception']

        return load_dns_bitmap(Log, bl_exc=bl_exceptions, wl_exc=wl_exceptions)


class Reachability:
    '''this class is used to determine whether a remote dns server has recovered from an outage or
    slow response times.'''

    __slots__ = (
        '_protocol', 'DNSServer', '_initialize',


        '_tls_context', '_udp_query'
    )

    def __init__(self, protocol, DNSServer):
        self._protocol = protocol
        self.DNSServer = DNSServer

        self._initialize = Initialize(Log, DNSServer.__name__)

        self._create_tls_context()

    @classmethod
    def run(cls, DNSServer):
        '''starting remote server responsiveness detection as a thread. the remote servers will only
        be checked for connectivity if they are mark as down during the polling interval.'''

        # initializing udp instance and starting thread
        reach_udp = cls(PROTO.UDP, DNSServer)
        reach_udp._set_udp_query()

        threading.Thread(target=reach_udp.udp).start()

        # initializing tls instance and starting thread
        reach_tls = cls(PROTO.DNS_TLS, DNSServer)
        threading.Thread(target=reach_tls.tls).start()

        # waiting for each thread to finish initial reachability check before returning
        reach_udp._initialize.wait_for_threads(count=1)
        reach_tls._initialize.wait_for_threads(count=1)

    @dynamic_looper
    def tls(self):
        if (self.is_enabled):

            DNSServer = self.DNSServer
            for secure_server in DNSServer.dns_servers:

                # no check needed if server/proto is known up
                if (secure_server[self._protocol]): continue

                # if server responds to connection attempt, it will be marked as available
                if self._tls_reachable(secure_server):
                    secure_server[PROTO.DNS_TLS] = True,
                    DNSServer.tls_up = True

                    Log.notice('DNS server {} has recovered on {}.'.format(secure_server['ip'], self._protocol.name))

                    # will write server status change individually as its unlikely both will be down at same time
                    write_configuration(DNSServer.dns_servers._asdict(), 'dns_server_status')

        self._initialize.done()

        return TEN_SEC

    def _tls_reachable(self, secure_server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        secure_socket = self._tls_context.wrap_socket(sock, server_hostname=secure_server)
        try:
            secure_socket.connect((secure_server, PROTO.DNS_TLS))
        except (OSError, socket.timeout):
            return False

        else:
            return True

        finally:
            secure_socket.close()

    @dynamic_looper
    def udp(self):
        if (self.is_enabled or self.DNSServer.udp_fallback):

            DNSServer = self.DNSServer
            for server in DNSServer.dns_servers:
                # no check needed if server/proto is known up
                if (server[self._protocol]): continue

                # if server responds to connection attempt, it will be marked as available
                if self._udp_reachable(server['ip']):
                    server[PROTO.UDP] = True

                    Log.notice('DNS server {} has recovered on {}.'.format(server['ip'], self._protocol.name))

                    write_configuration(self.DNSServer.dns_servers._asdict(), 'dns_server_status')

        self._initialize.done()

        return TEN_SEC

    def _udp_reachable(self, server_ip):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(self._udp_query, (server_ip, PROTO.DNS))
            sock.recv(1024)
        except socket.timeout:
            return False

        else:
            return True

        finally:
            sock.close()

    def _create_tls_context(self):
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._tls_context.verify_mode = ssl.CERT_REQUIRED
        self._tls_context.load_verify_locations(CERTIFICATE_STORE)

    def _set_udp_query(self):
        self._udp_query = byte_join([
            create_dns_query_header(dns_id=69, cd=1),
            b'\x0bdnxfirewall\x03com\x00\x00\x01\x00\x01'
        ])

    @property
    def is_enabled(self):
        return self._protocol == self.DNSServer.protocol
