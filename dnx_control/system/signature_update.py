#!/usr/bin/env python3

from __future__ import annotations

import os as _os
import os.path
import urllib.request as requests

# from dnx_gentools.def_constants import HOME_DIR

HOME_DIR: str = _os.environ.get('HOME_DIR', '/'.join(_os.path.realpath(__file__).split('/')[:-2]))

URL = 'https://raw.githubusercontent.com'
SIGNATURE_URL = f'{URL}/DOWRIGHTTV/dnxfirewall-signatures/master'

# this module will download all files directly from a github raw repository url.
def get_remote_version():
    # NOTE: this is a blocking call and will not return until the file is downloaded.

    # default version if the remote version cannot be determined. set to the highest calendar year/month/day
    remote_version = 99991231

    with requests.urlopen(f'{SIGNATURE_URL}/COMPATIBLE_VERSION') as response:

        remote_version = int(response.readlines()[-1].decode('utf-8'))

    return remote_version

def compare_signature_version() -> bool:

    local_version = 0
    remote_version = get_remote_version()

    # if the local version file does not exist, the signatures are not compatible and a system update is needed
    if not os.path.exists(f'{HOME_DIR}/dnx_system/signatures/COMPATIBLE_VERSION'):
        return False

    with open(f'{HOME_DIR}/dnx_system/signatures/COMPATIBLE_VERSION', 'r') as file:
        local_version = int(file.readlines()[-1])

    if (local_version < remote_version):
        return False

    return True

def get_remote_signature_list() -> list[str]:

    signature_manifest = []

    with requests.urlopen(f'{SIGNATURE_URL}/SIGNATURE_MANIFEST') as response:

        for line in response.readlines():
            line = line.decode('utf-8').strip().split()

            signature_list.append(tuple(line))

    return signature_list


print(compare_signature_version())
