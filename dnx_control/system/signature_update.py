#!/usr/bin/env python3

from __future__ import annotations

import os
import urllib.request as requests

from dnx_gentools.def_typing import *
from dnx_gentools.def_namedtuples import SigFile
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
# once all files are moved into place, the update flag will be reset

# PATH_SEPARATOR = '\\' if sys.platform == 'win32' else '/'
# HOME_DIR: str = '/'.join(os.path.realpath(__file__).split(PATH_SEPARATOR)[:-3])
# HOME_DIR: str = os.environ.get('HOME_DIR', '/'.join(os.path.realpath(__file__).split('/')[:-2]))

URL = 'https://raw.githubusercontent.com'
SIGNATURE_URL = f'{URL}/DOWRIGHTTV/dnxfirewall-signatures/update-candidate-1'

def format_downloaded_data(data: bytes) -> str:
    '''convert data to a format compatible with dnxfirewall and/or linux file systems.

        1. remove all comments from downloaded data
    '''
    data = '\n'.join([line for line in data.decode('utf-8').splitlines() if not line.startswith('#')])

    # re-adding trailing newline after split operation
    data += '\n'

    return data

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

def get_remote_version(filename: str) -> tuple[bool, int]:
    # downloading remote version file and removing all comments
    with requests.urlopen(f'{SIGNATURE_URL}/{filename}') as response:

        remote_version_data = format_downloaded_data(response.read())

        try:
            remote_version = int(remote_version_data.strip())
        except:
            # default version if the remote version cannot be determined. set to the highest calendar year/month/day
            return (True, 99991231)

    # writing version to temp file
    with open(f'dnx_profile/signatures/{filename}_TEMP', 'w') as file:
        file.write(remote_version_data)

    return (False, remote_version)

def validate_file_download(filename: str, remote_file_hash: str) -> bool:
    # if the file hash does not match the remote hash, the file was not downloaded correctly and will be deleted.
    # files with errors will be added to a list and reported back before the update proceeds.
    local_file_hash = calculate_file_hash(filename, folder='signatures')

    if (local_file_hash != remote_file_hash):
        os.remove(f'dnx_profile/signatures/{filename}')

        return False

    return True

def compare_signature_version(remote_version: int, *, system_update: bool = False) -> bool:
    # if the local version file does not exist, the signatures are not compatible and a system update is needed
    if not os.path.exists(f'dnx_profile/signatures/COMPATIBLE_VERSION'):

        # todo: removing this bypass because there could be a sync issue between signature and dnxfirewall repos.
        #  only applies to old version and would have to wait until the system repo update is applied.

        # system update will override compatibility check and allow the signatures to be updated.
        # if (system_update):
        #     return True

        return False

    with open(f'dnx_profile/signatures/COMPATIBLE_VERSION', 'r') as file:
        local_version = int(file.read().strip())

    if (local_version < remote_version):
        return False

    return True

def get_file_validations() -> list[tuple]:
    file_validations = []

    with requests.urlopen(f'{SIGNATURE_URL}/FILE_VALIDATION') as response:

        for line in response.readlines():
            line = line.decode('utf-8').strip().split()

            file_validations.append(tuple(line))

    return file_validations

def get_remote_signature_manifest(manifest_name: str) -> SIGNATURE_MANIFEST:
    signature_manifest = []

    # downloading remote version file and removing all comments
    with requests.urlopen(f'{SIGNATURE_URL}/{manifest_name}') as response:

        signature_manifest_data = format_downloaded_data(response.read())

        for file_data in signature_manifest_data.splitlines():
            folder, file_name = file_data[1].split('/')

            signature_manifest.append(
                SigFile(file_data[0], folder, file_name, file_data[2])
            )

    # writing the version to temp file
    with open(f'dnx_profile/signatures/{manifest_name}_TEMP', 'w') as file:
        file.write(signature_manifest_data)

    return signature_manifest

def check_for_file_changes(manifest_name: str, remote_signature_manifest: SIGNATURE_MANIFEST) -> tuple[SIGNATURE_MANIFEST, SIGNATURE_MANIFEST]:
    '''return list of signature files that have changed or are missing from the local system.
    '''

    # if file doesnt exist, but we made it to this point, then it is safe to proceed with updating all signature sets.
    try:
        with open(f'dnx_profile/signatures/{manifest_name}', 'r') as file:
            local_signature_manifest = file.read().splitlines()
    except FileNotFoundError:
        lsm_lookup = {}.get
    else:
        lsm_lookup = {line.split()[1]: line.split()[2] for line in local_signature_manifest}.get

    missing_files: SIGNATURE_MANIFEST = []
    changed_files: SIGNATURE_MANIFEST = []
    # comparing local and remote signature manifests to determine which files need to be updated.
    for target in remote_signature_manifest:

        local_hash = lsm_lookup(f'{target.folder}/{target.name}', None)
        if (local_hash is None):
            missing_files.append(target)

        elif (local_hash != target.checksum):

            changed_files.append(target)

    return missing_files, changed_files

def download_signature_file(target: SigFile) -> bool:
    # removing all comments before storing the signatures in the temp file.
    with requests.urlopen(f'{SIGNATURE_URL}/{target.folder}/{target.name}') as response:
        signatures = format_downloaded_data(response.read())

    system_path = get_file_path(target)

    try:
        temp_file = open(f'dnx_profile/{system_path}/temp/{target.name}', 'w')
    except:
        return False

    temp_file.write(signatures)
    temp_file.close()

    return True

def validate_signature_file(file_info: SigFile) -> bool:
    # if the file hash does not match the remote hash, the file was not downloaded correctly and will be deleted.
    # files with errors will be added to a list and reported back before the update proceeds.

    system_path = get_file_path(file_info)

    local_file_hash = calculate_file_hash(file_info.name, folder=system_path)
    if (local_file_hash != file_info.checksum):
        os.remove(f'dnx_profile/{file_info.folder}/temp/{file_info.name}')

        return False

    return True

def move_signature_files(signature_manifest: SIGNATURE_MANIFEST, failure_list: SIGNATURE_MANIFEST) -> None:

    for file_info in signature_manifest:
        folder, filename = get_file_path(file_info)

        if file_info in failure_list:
            continue

        os.rename(
            f'dnx_profile/{folder}/temp/{filename}',
            f'dnx_profile/{folder}/{filename}'
        )

    # replacing old compatible version file and signature file manifest
    os.rename('dnx_profile/signatures/COMPATIBLE_VERSION_TEMP', 'dnx_profile/signatures/COMPATIBLE_VERSION')
    os.rename('dnx_profile/signatures/SIGNATURE_MANIFEST_TEMP', 'dnx_profile/signatures/SIGNATURE_MANIFEST')

def create_sigfile(file_data: str) -> SigFile:

    folder, file_name = file_data[1].split('/')

    return SigFile(file_data[0], folder, file_name, file_data[2])

def get_file_path(file_info: SigFile) -> str:
    '''return the system folder path and filename for the specified file type.
    '''
    if (file_info.ftype == 'signature'):
        system_path = f'signatures/{file_info.folder}'

    elif (file_info.ftype == 'configuration'):
        system_path = f'data/system/security/{file_info.folder}'

    else:
        raise ValueError(f'invalid file type for {file_info.name}')  # this should never be hit

    return system_path

def cleanup_temp_files() -> None:
    try:
        os.remove('dnx_profile/signatures/COMPATIBLE_VERSION_TEMP')
        os.remove('dnx_profile/signatures/SIGNATURE_MANIFEST_TEMP')
    except FileNotFoundError:
        pass

