#!/usr/bin/env python3

from __future__ import annotations

# ================
# RUNTIME IMPORTS
# ================
from dnx_gentools.def_constants import INITIALIZE_MODULE

if INITIALIZE_MODULE('ips-ids'):
    __all__ = ('run',)

    from dnx_gentools.def_enums import Queue

    from ids_ips import IPS_IDS
    from ids_ips_log import Log

    Log.run(name='ips')


def run():
    IPS_IDS.run(Log, q_num=Queue.IPS_IDS)


# ================
# TYPING IMPORTS
# ================
from typing import TYPE_CHECKING, Type

if (TYPE_CHECKING):
    from typing import TypeAlias

    __all__ = (
        'IPS_IDS', 'IPSPacket',

        # TYPES
        'IPS_IDS_T', 'IPSPacket_T'
    )

    from ids_ips import IPS_IDS
    from ids_ips_packets import IPSPacket

    # ======
    # TYPES
    # ======
    IPS_IDS_T:   TypeAlias = Type[IPS_IDS]
    IPSPacket_T: TypeAlias = Type[IPSPacket]
