#!/usr/bin/env python3

from __future__ import annotations

# ================
# RUNTIME IMPORTS
# ================
from dnx_gentools.def_constants import INITIALIZE_MODULE

if INITIALIZE_MODULE('ip-proxy'):
    __all__ = ('run',)

    from dnx_gentools.def_enums import Queue
    from dnx_gentools.signature_operations import generate_reputation

    from dnx_iptools.hash_trie import HashTrie_Value

    from ip_proxy_log import Log

    Log.run(name='ip_proxy')

    reputation_signatures = generate_reputation(Log)

    # initializing the C/Cython extension, converting python structures to native C array/struct.
    # assigning direct reference to the search method [which calls underlying C without GIL]
    _reputation_trie = HashTrie_Value()
    _reputation_trie.generate_structure(reputation_signatures, len(reputation_signatures))

    # memory allocation was done manually within the C extension for its structures.
    # python structures are no longer needed at this point so freeing memory.
    del reputation_signatures

    # =================
    # DEFERRED IMPORTS
    # =================
    # must be imported after logger is initialized
    import ip_proxy

    # setting top of file variable for proxy direct access to search method
    ip_proxy.REP_LOOKUP = _reputation_trie.py_search


def run():
    ip_proxy.IPProxy.run(Log, q_num=Queue.IP_PROXY)


# ================
# TYPING IMPORTS
# ================
from typing import TYPE_CHECKING, Type

if (TYPE_CHECKING):
    __all__ = (
        'IPProxy', 'IPPPacket',

        # TYPES
        'IPProxy_T', 'IPPPacket_T'
    )

    from ip_proxy import IPProxy
    from ip_proxy_packets import IPPPacket

    # ======
    # TYPES
    # ======
    IPProxy_T = Type[IPProxy]
    IPPPacket_T = Type[IPPPacket]
