#!/usr/bin/env python3

from __future__ import annotations

import os
import urllib.request as requests

from dnx_gentools.file_operations import ConfigurationManager, calculate_file_hash

# update signature files from the github dnxfirewall-signatures repo.
# a version check will be done to ensure the signatures are compatible with the current system version.
# if they are not compatible, an error will be raised to update the system first, which will also update the signatures.

# each remote signature file will be checked with a hash to ensure the download was complete.
# if all signatures are downloaded successfully, each file will be atomically moved into place.
# if there is a system failure during the update, it is possible that only some signature files were updated.
#   - this will not cause any issues. the system will continue to use the old signatures until the update is complete.
#   - an update flag will be used to identify whether all signatures were updated successfully.
#       - the update flag can be checked via the command line interface. (maybe will add a webui alert in the future)
# once all files are moved into place the update flag will be reset

# PATH_SEPARATOR = '\\' if sys.platform == 'win32' else '/'
# HOME_DIR: str = '/'.join(os.path.realpath(__file__).split(PATH_SEPARATOR)[:-3])
# HOME_DIR: str = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-2]))

URL = 'https://raw.githubusercontent.com'
SIGNATURE_URL = f'{URL}/DOWRIGHTTV/dnxfirewall-signatures/master'

# set/clear will be used to identify a system failure during a signature update.
def set_signature_update_flag(*, override: bool = False) -> bool:
    with ConfigurationManager('system', cfg_type='global') as dnx_settings:
        config = dnx_settings.load_configuration()

        if config['signature_update'] and not override:
            return False

        config['signature_update'] = 1

        dnx_settings.write_configuration(config.expanded_user_data)

    return True

def clear_signature_update_flag() -> None:
    with ConfigurationManager('system', cfg_type='global') as dnx_settings:
        config = dnx_settings.load_configuration()

        config['signature_update'] = 0

        dnx_settings.write_configuration(config.expanded_user_data)

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
    if not os.path.exists(f'dnx_profile/signatures/COMPATIBLE_VERSION'):
        return False

    with open(f'dnx_profile/signatures/COMPATIBLE_VERSION', 'r') as file:
        local_version = int(file.readlines()[-1])

    if (local_version < remote_version):
        return False

    return True

def get_remote_signature_manifest() -> list[tuple]:

    signature_manifest = []

    with requests.urlopen(f'{SIGNATURE_URL}/SIGNATURE_MANIFEST') as response:

        for line in response.readlines():
            line = line.decode('utf-8').strip().split()

            signature_manifest.append(tuple(line))

    return signature_manifest

def download_signature_file(file: str) -> bool:

    with requests.urlopen(f'{SIGNATURE_URL}/{file}') as remote_signatures_file:
        signatures = remote_signatures_file.read().decode('utf-8')

    folder, filename = file.split('/')
    # print('writing file: ', folder + '/temp/' + filename)

    try:
        temp_file = open(f'dnx_profile/signatures/{folder}/temp/{filename}', 'w')
    except:
        return False

    temp_file.write(signatures)
    temp_file.close()

    return True

def validate_signature_file(file: str, remote_file_hash: str) -> bool:
    # if the file hash does not match the remote hash, the file was not downloaded correctly and will be deleted.
    # files with errors will be added to a list and reported back before the update proceeds.
    folder, filename = file.split('/')

    local_file_hash = calculate_file_hash(filename, folder=f'signatures/{folder}/temp')
    if (local_file_hash != remote_file_hash):
        os.remove(f'dnx_profile/signatures/{folder}/temp/{filename}')

        return False

    return True

def move_signature_files(signature_manifest: list[tuple], failure_list: list[tuple]) -> None:

    for file, file_hash in signature_manifest:
        folder, filename = file.split('/')

        if (file, file_hash) in failure_list:
            continue

        # print(f'moving file {folder}/temp/{filename} -> {folder}/{filename}')

        os.rename(
            f'dnx_profile/signatures/{folder}/temp/{filename}',
            f'dnx_profile/signatures/{folder}/{filename}'
        )
