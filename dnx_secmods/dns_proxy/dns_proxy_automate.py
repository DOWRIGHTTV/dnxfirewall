#!/usr/bin/env python3

from __future__ import annotations

import threading
import socket
import ssl

from ipaddress import IPv4Address

from dnx_gentools.def_constants import *
from dnx_gentools.def_typing import *
from dnx_gentools.def_enums import PROTO, TLD_CAT
from dnx_gentools.file_operations import *
from dnx_gentools.standard_tools import looper, Initialize

from dnx_iptools.protocol_tools import create_dns_query_header, convert_string_to_bitmap

from dns_proxy_log import Log

ConfigurationManager.set_log_reference(Log)


class Configuration:
    _proxy_setup:  ClassVar[bool] = False
    _server_setup: ClassVar[bool] = False
    _keywords: ClassVar[list] = []

    __slots__ = (
        # callbacks
        'dns_proxy', 'dns_server',

        '_initialize',
    )

    def __init__(self, name: str) -> None:
        self._initialize = Initialize(Log, name)

    @classmethod
    def proxy_setup(cls, dns_proxy: Type[DNSProxy]) -> None:
        '''start threads for tasks required by the DNS proxy. blocking until settings are loaded/initialized.'''
        if (cls._proxy_setup):
            raise RuntimeError('proxy setup should only be called once.')

        cls._proxy_setup = True

        # NOTE: might be temporary, but this needed to be moved outside the standard/bitmap sigs since they are
        # now being handled by an external C extension (cython)
        cls._keywords = load_keywords(log=Log)

        self = cls(dns_proxy.__name__)
        self.dns_proxy = dns_proxy

        threading.Thread(target=self._get_proxy_settings).start()
        threading.Thread(target=self._get_list, args=('whitelist',)).start()
        threading.Thread(target=self._get_list, args=('blacklist',)).start()

        self._initialize.wait_for_threads(count=3)

    @classmethod
    def server_setup(cls, dns_server: Type[DNSServer]) -> None:
        '''start threads for tasks required by the DNS server.

        This will ensure all automated threads get started, including reachability. blocking until settings are
        loaded/initialized.'''

        if (cls._server_setup):
            raise RuntimeError('server setup should only be called once.')
        cls._server_setup = True

        self = cls(dns_server.__name__)

        threading.Thread(target=self._get_server_settings, args=(dns_server,)).start()

        self._initialize.wait_for_threads(count=1)

    @cfg_read_poller('dns_proxy')
    def _get_proxy_settings(self, cfg_file: str) -> None:
        dns_proxy = load_configuration(cfg_file)

        signatures = self.dns_proxy.signatures
        # CATEGORY SETTINGS
        enabled_keywords = []
        for cat, setting in dns_proxy.get_items('categories->default'):
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
        # copying the keyword signature list in memory to a local object then iterating over the list. if the current
        # item category is not an enabled category, the signature will get removed and the offset will get adjusted to
        # normalize the index.
        mem_keywords, offset = signatures.keyword.copy(), 0
        for i, signature in enumerate(mem_keywords):

            _, cat = signature
            if (cat not in enabled_keywords):
                signatures.keyword.pop(i-offset)
                offset += 1

        # iterating over keywords from the signature set. if the keyword category is enabled and the current
        # signature is not already in memory it will be added.
        for signature, cat in self._keywords:

            if (cat in enabled_keywords and signature not in signatures.keyword):
                signatures.keyword.append((signature, cat))

        # TLD SETTINGS | generator
        for tld, setting in load_tlds():
            signatures.tld[tld] = setting

        self._initialize.done()

    @cfg_read_poller('dns_server')
    def _get_server_settings(self, dns_server: Type[DNSServer], cfg_file: str) -> None:
        dns_settings = load_configuration(cfg_file)

        tls_enabled = dns_settings['tls->enabled']
        dns_server.udp_fallback = dns_settings['tls->fallback']

        dns_server.protocol = PROTO.DNS_TLS if tls_enabled else PROTO.UDP

        names = ['primary', 'secondary']
        for name, cfg_server, mem_server in zip(names, dns_settings.get_values('resolvers'), dns_server.dns_servers):

            if (cfg_server['ip_address'] != mem_server['ip']):

                # setting server status as false on initialization or server change by user.
                # this will require reachability to succeed before it will be actively used.
                getattr(dns_server.dns_servers, name).update({
                    'ip': dns_settings[f'resolvers->{name}->ip_address'],
                    PROTO.UDP: False, PROTO.DNS_TLS: False
                })

        dns_server.dns_records = dns_settings['records']

        self._initialize.done()

    @cfg_write_poller
    # handles updating user defined signatures in memory/propagated changes to disk.
    def _get_list(self, lname: str, cfg_file: str, last_modified_time: int) -> float:
        memory_list = getattr(self.dns_proxy, lname).dns

        timeout_detected = self._check_for_timeout(memory_list)
        # if a rule timeout is detected for an entry in memory. we will update the config file
        # to align with active rules, then we will remove the rules from memory.
        if (timeout_detected):
            loaded_list = self._update_list_file(cfg_file)

            self._modify_memory(memory_list, loaded_list, action=CFG.DEL)

        # if the file has been modified, the list will be referenced to make in place changes to the list in memory,
        # specifically around adding new rules and the new modified time will be returned. if not modified,
        # the last modified time is returned and not changes are made.
        try:
            modified_time = os.stat(f'{HOME_DIR}/dnx_system/data/usr/{cfg_file}').st_mtime
        except FileNotFoundError:
            modified_time = os.stat(f'{HOME_DIR}/dnx_system/data/{cfg_file}').st_mtime

        if (modified_time == last_modified_time):
            return last_modified_time

        loaded_list = load_configuration(cfg_file)

        self._modify_memory(memory_list, loaded_list, action=CFG.ADD)

        # ip whitelist specific. will do an inplace swap of all rules needing to be added or removed in memory.
        if (lname == 'whitelist'):
            self._modify_ip_whitelist(cfg_file, self.dns_proxy.whitelist.ip)

        self._initialize.done()

        return modified_time

    @staticmethod
    def _modify_memory(memory_list: dict, loaded_list: ConfigChain, *, action: CFG) -> None:
        '''removing/adding signature/rule from memory as needed.'''
        if (action is CFG.ADD):

            # iterating over rules/signatures pulled from file
            for rule, settings in loaded_list.get_items('time_based'):
                bitmap_key = convert_string_to_bitmap(rule, DNS_BIN_OFFSET)

                # adding rule/signature to memory if not present
                if (bitmap_key not in memory_list):
                    settings['key'] = rule
                    memory_list[bitmap_key] = settings

        if (action is CFG.DEL):

            # iterating over rules/signature in memory
            for rule, settings in memory_list.copy().items():

                bitmap_key = convert_string_to_bitmap(rule, DNS_BIN_OFFSET)

                # if the rule is not present in the config file, it will be removed from memory
                if (settings['key'] not in loaded_list):
                    memory_list.pop(bitmap_key, None)

    @staticmethod
    def _modify_ip_whitelist(cfg_file: str, memory_ip_list: dict) -> None:
        loaded_ip_list = load_configuration(cfg_file)

        # iterating over ip rules in memory.
        for ip in memory_ip_list.copy():

            # if it is not in the config file it will be removed.
            if (f'{ip}' not in loaded_ip_list):
                memory_ip_list.pop(ip, None)

        # iterating over ip rules in configuration file
        for ip, settings in loaded_ip_list.get_items('ip_bypass'):
            # convert to an ip address object which is the type stored as the key
            ip = IPv4Address(ip)

            # if it is not in memory and the rule type is "global" it will be added
            if (ip not in memory_ip_list and settings['type'] == 'global'):
                memory_ip_list[ip] = True

    @staticmethod
    # checking the corresponding list file for any time based rules timing out. will return True if timeout
    # is detected otherwise return False.
    def _check_for_timeout(lname_dns: Dict) -> bool:
        now = fast_time()
        for info in lname_dns.values():

            if (now >= info['expire']):
                return True

        return False

    @staticmethod
    # updating the file with necessary changes.
    def _update_list_file(cfg_file: str) -> ConfigChain:
        now = fast_time()
        with ConfigurationManager(cfg_file) as dnx:
            lists = dnx.load_configuration()

            loaded_list = lists.get_items('time_based')
            for domain, info in loaded_list:

                if (now >= info['expire']):
                    del lists[f'time_based->{domain}']

            dnx.write_configuration(lists.expanded_user_data)

            return lists


class Reachability:
    '''this class is used to determine whether a remote dns server has recovered from an outage or
    slow response times.'''

    __slots__ = (
        '_protocol', 'dns_server', '_initialize',

        '_tls_context', '_udp_query',
    )

    def __init__(self, protocol: PROTO, dns_server: Type[DNSServer]):
        self._protocol = protocol
        self.dns_server = dns_server

        self._initialize = Initialize(Log, dns_server.__name__)

    @classmethod
    def run(cls, dns_server: Type[DNSServer]):
        '''starting remote server responsiveness detection as a thread. the remote servers will only be checked for
        connectivity if they are marked as down during the polling interval. both UDP and TLS(TCP) will be started
        with one call to run.'''

        # initializing udp instance and starting thread
        reach_udp = cls(PROTO.UDP, dns_server)
        reach_udp._set_udp_query()

        threading.Thread(target=reach_udp.udp).start()

        # initializing tls instance and starting thread
        reach_tls = cls(PROTO.DNS_TLS, dns_server)
        reach_tls._create_tls_context()

        threading.Thread(target=reach_tls.tls).start()

        # waiting for each thread to finish initial reachability check before returning
        reach_udp._initialize.wait_for_threads(count=1)
        reach_tls._initialize.wait_for_threads(count=1)

    @looper(FIVE_SEC)
    def tls(self):
        if (self.is_enabled):

            for secure_server in self.dns_server.dns_servers:

                # no check needed if server/proto is known up
                if (secure_server[self._protocol]): continue

                Log.debug(f'[{secure_server["ip"]}/{self._protocol.name}] Checking reachability of remote DNS server.')

                # if server responds to connection attempt, it will be marked as available
                if self._tls_reachable(secure_server['ip']):
                    secure_server[PROTO.DNS_TLS] = True
                    self.dns_server.tls_down = False

                    Log.notice(f'[{secure_server["ip"]}/{self._protocol.name}] DNS server is reachable.')

                    # will write server status change individually as its unlikely both will be down at same time
                    write_configuration(self.dns_server.dns_servers._asdict(), 'dns_server_status')

        self._initialize.done()

    def _tls_reachable(self, secure_server: str) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)

        secure_socket = self._tls_context.wrap_socket(sock, server_hostname=secure_server)
        try:
            secure_socket.connect((secure_server, PROTO.DNS_TLS))
        except OSError:
            return False

        else:
            return True

        finally:
            secure_socket.close()

    @looper(FIVE_SEC)
    def udp(self):
        if (self.is_enabled or self.dns_server.udp_fallback):

            for server in self.dns_server.dns_servers:

                # no check needed if server/proto is known up
                if (server[self._protocol]): continue

                Log.debug(f'[{server["ip"]}/{self._protocol.name}] Checking reachability of remote DNS server.')

                # if server responds to connection attempt, it will be marked as available
                if self._udp_reachable(server['ip']):
                    server[PROTO.UDP] = True

                    Log.notice(f'[{server["ip"]}/{self._protocol.name}] DNS server is reachable.')

                    write_configuration(self.dns_server.dns_servers._asdict(), 'dns_server_status')

        self._initialize.done()

    def _udp_reachable(self, server_ip: str) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(self._udp_query, (server_ip, PROTO.DNS))
            sock.recv(1024)
        except OSError:
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
        self._udp_query = bytearray(
            create_dns_query_header(dns_id=69, cd=1)
        ) + b'\x0bdnxfirewall\x03com\x00\x00\x01\x00\x01'

    @property
    def is_enabled(self) -> bool:
        return self._protocol == self.dns_server.protocol
