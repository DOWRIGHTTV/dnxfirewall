#!/usr/bin/env python3

from __future__ import annotations

# ================
# RUNTIME IMPORTS
# ================
from dnx_gentools.def_constants import INITIALIZE_MODULE

if INITIALIZE_MODULE('ips-ids'):
    __all__ = ('run',)

    from dnx_gentools.def_enums import Queue

    from ips_ids import IPS_IDS
    from ips_ids_log import Log

    Log.run(name='ips')


def run():
    IPS_IDS.run(Log, q_num=Queue.IPS_IDS)


# ================
# TYPING IMPORTS
# ================
from typing import TYPE_CHECKING, Type

if (TYPE_CHECKING):
    __all__ = (
        'IPS_IDS', 'IPSPacket',

        # TYPES
        'IPS_IDS_T', 'IPSPacket_T'
    )

    from ips_ids import IPS_IDS
    from ips_ids_packets import IPSPacket

    # ======
    # TYPES
    # ======
    IPS_IDS_T = Type[IPS_IDS]
    IPSPacket_T = Type[IPSPacket]
