#!/usr/bin/env python3

from __future__ import annotations

# ================
# RUNTIME IMPORTS
# ================
from dnx_gentools.def_constants import TYPE_CHECKING, INITIALIZE_MODULE

if INITIALIZE_MODULE('ids-ips'):
    __all__ = ('run',)

    from dnx_gentools.def_enums import Queue

    from ids_ips_log import Log

    Log.run(name='ips')

    import ids_ips


def run():
    try:
        ids_ips.IDS_IPS.run(Log, q_num=Queue.IDS_IPS)
    except Exception as e:
        Log.error(f'Error in IDS_IPS.run: {e}')
        raise

# ================
# TYPING IMPORTS
# ================
if (TYPE_CHECKING):
    from dnx_gentools.def_typing import TypeAlias, Type

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
