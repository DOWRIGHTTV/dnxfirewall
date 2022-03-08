#!/usr/bin/env python3

from __future__ import annotations

import os
import threading
import socket
import ssl

from ipaddress import IPv4Address

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import *
from dnx_gentools.def_namedtuples import DNS_SERVERS, DNS_SIGNATURES, DNS_WHITELIST, DNS_BLACKLIST, Item
from dnx_gentools.def_enums import PROTO, CFG, DNS_CAT
from dnx_gentools.file_operations import *
from dnx_gentools.standard_tools import looper, ConfigurationMixinBase, Initialize

from dnx_iptools.cprotocol_tools import iptoi
from dnx_iptools.protocol_tools import create_dns_query_header, convert_string_to_bitmap

from dns_proxy_log import Log

__all__ = (
    'ProxyConfiguration', 'ServerConfiguration', 'Reachability'
)

ConfigurationManager.set_log_reference(Log)


class ProxyConfiguration(ConfigurationMixinBase):
    '''DNS proxy configuration Mixin.
    '''
    # dns | ip
    whitelist: ClassVar[DNS_WHITELIST] = DNS_WHITELIST(
        {}, {}
    )
    blacklist: ClassVar[DNS_BLACKLIST] = DNS_BLACKLIST(
        {}
    )

    # en_dns | tld | keyword |
    # NOTE: dns signatures are contained within the binary search extension as a closure
    signatures: ClassVar[DNS_SIGNATURES] = DNS_SIGNATURES(
        {DNS_CAT.doh}, {}, []
    )

    _keywords: ClassVar[list[tuple[str, DNS_CAT]]] = []

    def _configure(self) -> tuple[LogHandler_T, tuple]:
        '''return thread information to be run.

         tasks required by the DNS proxy.
         '''
        # NOTE: might be temporary, but this needed to be moved outside the standard/bitmap sigs since they are
        # now being handled by an external C extension (cython)
        self.__class__._keywords = load_keywords(log=Log)

        threads = (
            (self._get_proxy_settings, ()),
            (self._get_list, ('whitelist',)),
            (self._get_list, ('blacklist',))
        )

        return Log, threads

    @cfg_read_poller('dns_proxy')
    def _get_proxy_settings(self, cfg_file: str) -> None:
        proxy_config: ConfigChain = load_configuration(cfg_file)

        signatures: DNS_SIGNATURES = self.__class__.signatures
        # CATEGORY SETTINGS
        enabled_keywords: list[DNS_CAT] = []
        for cat, setting in proxy_config.get_items('categories->default'):
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
        # copying the keyword signature list in memory to a local object, then iterating over the list.
        # if the current category is not enabled, the signature will get removed and the offset will get normalized to
        # the index.
        # NOTE: this is not entirely thread safe
        mem_keywords, offset = signatures.keyword.copy(), 0
        for i, signature in enumerate(mem_keywords):

            _, cat = signature
            if (cat not in enabled_keywords):
                signatures.keyword.pop(i-offset)
                offset += 1

        # iterating over keywords from the signature set. if the keyword category is enabled and the current
        # signature is not in memory, it will be added.
        for signature, cat in self._keywords:

            if (cat in enabled_keywords and signature not in signatures.keyword):
                signatures.keyword.append((signature, cat))

        # TLD SETTINGS | generator
        for tld, setting in load_tlds():
            signatures.tld[tld] = setting

        self._initialize.done()

    @cfg_write_poller
    # handles updating user defined signatures in memory/propagated changes to disk.
    def _get_list(self, lname: str, cfg_file: str, last_modified_time: int) -> float:
        memory_list: dict = getattr(self.__class__, lname).dns

        timeout_detected: bool = self._check_for_timeout(memory_list)
        # if a rule timeout is detected for an entry in memory. we will update the config file
        # to align with active rules, then we will remove the rules from memory.
        if (timeout_detected):
            loaded_list = self._update_list_file(cfg_file)

            self._modify_memory(memory_list, loaded_list, action=CFG.DEL)

        # if the file has been modified, the list will be referenced to make in place changes to the list in memory,
        # specifically around adding new rules and the new modified time will be returned. if not modified,
        # the last modified time is returned and not changes are made.
        # NOTE: files need extensions due to changes to file operations. these functions will be reworked soon anyway.
        try:
            modified_time = os.stat(f'{HOME_DIR}/dnx_system/data/usr/{cfg_file}.cfg').st_mtime
        except FileNotFoundError:
            modified_time = os.stat(f'{HOME_DIR}/dnx_system/data/{cfg_file}.cfg').st_mtime

        if (modified_time == last_modified_time):
            return last_modified_time

        loaded_list = load_configuration(cfg_file)

        self._modify_memory(memory_list, loaded_list, action=CFG.ADD)

        # ip whitelist specific. will do an inplace swap of all rules needing to be added or removed in memory.
        if (lname == 'whitelist'):
            self._modify_ip_whitelist(cfg_file, self.__class__.whitelist.ip)

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
        loaded_ip_list: ConfigChain = load_configuration(cfg_file)

        # iterating over ip rules in memory.
        for ip in memory_ip_list.copy():

            # if it is not in the config file it will be removed.
            if (f'{ip}' not in loaded_ip_list):
                memory_ip_list.pop(ip, None)

        # iterating over ip rules in configuration file
        for ip, settings in loaded_ip_list.get_items('ip_bypass'):

            # FIXME: this needs to be converted to int on the backend
            # convert to an ip address object which is the type stored as the key
            ip = IPv4Address(ip)

            # if it is not in memory and the rule type is "global" it will be added
            if (ip not in memory_ip_list and settings['type'] == 'global'):
                memory_ip_list[ip] = True

    @staticmethod
    # will return True if timeout is detected otherwise return False.
    def _check_for_timeout(lname_dns: dict) -> bool:
        '''check the passed in list file by name for any time-based rules that have expired.
        '''
        now = fast_time()
        for info in lname_dns.values():

            if (now >= info['expire']):
                return True

        return False

    @staticmethod
    # updating the file with necessary changes.
    def _update_list_file(cfg_file: str) -> ConfigChain:
        now: int = fast_time()
        with ConfigurationManager(cfg_file) as dnx:
            lists = dnx.load_configuration()

            loaded_list: list[Item] = lists.get_items('time_based')
            for domain, info in loaded_list:

                if (now >= info['expire']):
                    del lists[f'time_based->{domain}']

            dnx.write_configuration(lists.expanded_user_data)

            return lists


class ServerConfiguration(ConfigurationMixinBase):
    '''DNS Server configuration Mixin.
    '''
    protocol: ClassVar[PROTO] = PROTO.NOT_SET
    tls_down: ClassVar[bool] = True
    udp_fallback: ClassVar[bool] = False
    keepalive_interval: ClassVar[int] = 8

    # NOTE: setting values to None to denote initialization has not been completed.
    public_resolvers: ClassVar[DNS_SERVERS] = DNS_SERVERS(
        {'ip_address': None, PROTO.UDP: None, PROTO.DNS_TLS: None},
        {'ip_address': None, PROTO.UDP: None, PROTO.DNS_TLS: None}
    )

    dns_records: ClassVar[dict[str, int]] = {}

    def _configure(self) -> tuple:
        '''return thread information to be run.

         tasks required by the DNS server.
         '''
        return Log, ((self._get_server_settings, ()),)

    @cfg_read_poller('dns_server')
    def _get_server_settings(self, cfg_file: str) -> None:
        server_config: ConfigChain = load_configuration(cfg_file)

        self.__class__.protocol = PROTO.DNS_TLS if server_config['tls->enabled'] else PROTO.UDP
        self.__class__.udp_fallback = server_config['tls->fallback']

        # in place swap of dns servers if they have changed
        loaded_resolvers = server_config.get_values('resolvers')
        configured_resolvers = self.__class__.public_resolvers

        for i, resolver in enumerate(loaded_resolvers):

            # setting server status as false on initialization or server change by user.
            # this will require reachability to succeed before it will be actively used.
            if (resolver['ip_address'] != configured_resolvers[i]['ip_address']):

                configured_resolvers[i].update({
                    'ip_address': resolver['ip_address'],
                    PROTO.UDP: False, PROTO.DNS_TLS: False
                })

        # inplace swap of dns servers from configuration to memory
        # copy allows for mutating the dict as we iterate
        for name, ip_addr in self.__class__.dns_records.copy():

            # removing if record was removed in webui
            if name not in server_config.get_dict('records'):
                self.__class__.dns_records.pop(name)

        # a direct update is fine after we have cleared the removed records
        self.__class__.dns_records.update({
            name: iptoi(ip_addr) for name, ip_addr in server_config.get_dict('records').items()
        })

        self._initialize.done()


# TODO: not sure if i like how this class is a class. it just makes me feel weird.
class Reachability:
    '''this class is used to determine whether a remote dns server has recovered from an outage or
    slow response times.
    '''
    _dns_server: ClassVar[DNSServer_T] = None

    __slots__ = (
        '_protocol', '_initialize',

        '_tls_context', '_udp_query',
    )

    def __init__(self, protocol: PROTO):
        self._protocol: PROTO = protocol

        self._initialize = Initialize(Log, self.__class__.__name__)

        self._tls_context: SSLContext

    @classmethod
    def run(cls, dns_server: DNSServer_T):
        '''starting remote server responsiveness detection as a thread.

        the remote servers will only be checked for connectivity if they are marked as down during the polling interval.
        both UDP and TLS(TCP) will be started with one call to run.
        '''
        cls._dns_server = dns_server

        # initializing udp instance and starting thread
        reach_udp = cls(PROTO.UDP)
        reach_udp._set_udp_query()

        threading.Thread(target=reach_udp.udp).start()

        # initializing tls instance and starting thread
        reach_tls = cls(PROTO.DNS_TLS)
        reach_tls._create_tls_context()

        threading.Thread(target=reach_tls.tls).start()

        # waiting for each thread to finish initial reachability check before returning
        reach_udp._initialize.wait_for_threads(count=1)
        reach_tls._initialize.wait_for_threads(count=1)

    @looper(FIVE_SEC)
    def tls(self):
        if (self.is_enabled):

            for secure_server in self._dns_server.public_resolvers:

                # no check needed if server/proto is known up
                if (secure_server[self._protocol]):
                    continue

                Log.debug(
                    f'[{secure_server["ip_address"]}/{self._protocol.name}] Checking reachability of remote DNS server.'
                )

                # if the server responds to a connection attempt, it will be marked as available
                if self._tls_reachable(secure_server['ip_address']):
                    secure_server[PROTO.DNS_TLS] = True
                    self._dns_server.tls_down = False

                    Log.notice(f'[{secure_server["ip_address"]}/{self._protocol.name}] DNS server is reachable.')

                    # will write server status change individually as its unlikely both will be down at same time
                    write_configuration(self._dns_server.public_resolvers._asdict(), 'dns_server_status')

        self._initialize.done()

    def _tls_reachable(self, secure_server: str) -> bool:
        sock: Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        if (self.is_enabled or self._dns_server.udp_fallback):

            for server in self._dns_server.public_resolvers:

                # no check needed if server/proto is known up
                if (server[self._protocol]):
                    continue

                Log.debug(f'[{server["ip_address"]}/{self._protocol.name}] Checking reachability of remote DNS server.')

                # if the server responds to a connection attempt, it will be marked as available
                if self._udp_reachable(server['ip_address']):
                    server[PROTO.UDP] = True

                    Log.notice(f'[{server["ip_address"]}/{self._protocol.name}] DNS server is reachable.')

                    write_configuration(self._dns_server.public_resolvers._asdict(), 'dns_server_status')

        self._initialize.done()

    # NOTE: UDP can reuse its socket. consider slimming this down to just a send/recv and no socket close.
    def _udp_reachable(self, server_ip: str) -> bool:
        sock: Socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
        return self._protocol == self._dns_server.protocol
