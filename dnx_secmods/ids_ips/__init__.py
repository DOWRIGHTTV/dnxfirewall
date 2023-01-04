#!/usr/bin/env python3

from __future__ import annotations

# ================
# RUNTIME IMPORTS
# ================
from dnx_gentools.def_constants import INITIALIZE_MODULE

if INITIALIZE_MODULE('ips-ids'):
    __all__ = ('run',)

    from dnx_gentools.def_enums import Queue

    from ids_ips import IDS_IPS
    from ids_ips_log import Log

    Log.run(name='ips')


def run():
    IDS_IPS.run(Log, q_num=Queue.IDS_IPS)


# ================
# TYPING IMPORTS
# ================
from typing import TYPE_CHECKING, Type

if (TYPE_CHECKING):
    from typing import TypeAlias

    __all__ = (
        'IDS_IPS', 'IPSPacket',

        # TYPES
        'IDS_IPS_T', 'IPSPacket_T'
    )

    from ids_ips import IDS_IPS
    from ids_ips_packets import IPSPacket

    # ======
    # TYPES
    # ======
    IDS_IPS_T:   TypeAlias = Type[IDS_IPS]
    IPSPacket_T: TypeAlias = Type[IPSPacket]
