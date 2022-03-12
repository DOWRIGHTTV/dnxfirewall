#!/usr/bin/env python3

from __future__ import annotations

from dnx_gentools.def_constants import INITIALIZE_MODULE

if INITIALIZE_MODULE('dns-proxy'):
    __all__ = ('run',)

    import threading

    from dnx_gentools.def_enums import Queue
    from dnx_gentools.signature_operations import generate_domain

    from dnx_iptools.dnx_trie_search import RecurveTrie

    from dns_proxy_log import Log

    Log.run(name='dns_proxy')

    # TODO: collisions were found in the geolocation filtering data structure. this has been fixed for geolocation and
    #  standard ip category filtering, but has not been investigated for dns signatures. due to the way the signatures
    #  are compressed, it is much less likely to happen to dns signatures. (main issue were values in multiples of 10
    #  because of the multiple 0s contained).
    #  to be safe, run through the signatures, generate bin and host id, then check for host id collisions within a bin.
    dns_cat_signatures = generate_domain(Log)

    _category_trie = RecurveTrie()
    _category_trie.generate_structure(dns_cat_signatures)

    # =================
    # DEFERRED IMPORTS
    # =================
    # must be imported after logger is initialized
    import dns_proxy
    import dns_proxy_server

    # setting top of file variable for proxy direct access to search method
    dns_proxy.CAT_LOOKUP = _category_trie.search

def run():
    # server running in thread because run method is a blocking call
    threading.Thread(
        target=dns_proxy_server.DNSServer.run, args=(Log,), kwargs={'threaded': False, 'always_on': True}
    ).start()

    dns_proxy.DNSProxy.run(Log, q_num=Queue.DNS_PROXY)


# ===============
# TYPING IMPORTS
# ===============
from typing import TYPE_CHECKING, Type
if (TYPE_CHECKING):

    __all__ = (
        'DNSProxy', 'DNSServer',
        'ClientQuery', 'DNSPacket',
        'request_tracker', 'dns_cache',

        # TYPES
        'DNSProxy_T', 'DNSServer_T', 'DNSPacket_T'
    )

    # referencing some objects through proxy import references
    from dns_proxy import DNSProxy
    from dns_proxy_server import DNSServer
    from dns_proxy_packets import ClientQuery, DNSPacket
    from dns_proxy_cache import request_tracker, dns_cache

    # ======
    # TYPES
    # ======
    DNSProxy_T = Type[DNSProxy]
    DNSServer_T = Type[DNSServer]
    DNSPacket_T = Type[DNSPacket]
