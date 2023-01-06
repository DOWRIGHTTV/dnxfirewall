#!/usr/bin/env python3

from __future__ import annotations

# ================
# RUNTIME IMPORTS
# ================
from dnx_gentools.def_constants import INITIALIZE_MODULE

if INITIALIZE_MODULE('dns-proxy'):
    __all__ = ('run',)

    import threading

    from dnx_gentools.def_enums import Queue
    from dnx_gentools.signature_operations import generate_domain

    from dnx_iptools.hash_trie import HashTrie_Value

    from dns_proxy_log import Log

    Log.run(name='dns_proxy')

    dns_cat_signatures = generate_domain(Log)

    _category_trie = HashTrie_Value()
    _category_trie.generate_structure(dns_cat_signatures, len(dns_cat_signatures))

    # memory allocation was done manually within the C extension for its structures.
    # python structures are no longer needed at this point so freeing memory.
    del dns_cat_signatures

    # =================
    # DEFERRED IMPORTS
    # =================
    # must be imported after logger is initialized
    import dns_proxy
    import dns_proxy_server

    # setting top of file variable for proxy direct access to search method
    dns_proxy.CAT_LOOKUP = _category_trie.py_search

def run():
    # server running in thread because run method is a blocking call
    threading.Thread(
        target=dns_proxy_server.DNSServer.run, args=(Log,), kwargs={'always_on': True}
    ).start()

    dns_proxy.DNSProxy.run(Log, q_num=Queue.DNS_PROXY)


# ================
# TYPING IMPORTS
# ================
from typing import TYPE_CHECKING

if (TYPE_CHECKING):
    from typing import Type, TypeAlias

    __all__ = (
        'DNSProxy', 'DNSServer',
        'ClientQuery', 'DNSPacket',

        'DNSCache_T',

        # TYPES
        'DNSProxy_T', 'DNSServer_T', 'DNSPacket_T'
    )

    # referencing some objects through proxy import references
    from dns_proxy import DNSProxy
    from dns_proxy_server import DNSServer
    from dns_proxy_packets import ClientQuery, DNSPacket

    from dns_proxy_cache import DNSCache_T

    # ======
    # TYPES
    # ======
    DNSProxy_T:  TypeAlias = Type[DNSProxy]
    DNSServer_T: TypeAlias = Type[DNSServer]
    DNSPacket_T: TypeAlias = Type[DNSPacket]
