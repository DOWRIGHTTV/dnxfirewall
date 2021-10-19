#!/usr/bin/env python3

import os
import json
import time
import shutil
import hashlib
import subprocess

from fcntl import flock, LOCK_EX, LOCK_UN
from secrets import token_urlsafe
from collections import defaultdict

from dnx_gentools.def_constants import HOME_DIR, USER, GROUP, FILE_POLL_TIMER, str_join
from dnx_gentools.def_constants import DNS_BIN_OFFSET, DNS_CAT
from dnx_sysmods.configure.exceptions import ValidationError

# will load json data from file, convert it to a python dict, then return as object
# TODO: add usr config support, which will merge will loaded system defaults.
#  !! currently supported, but in the case of nested dicts the user config overrides
#  system settings, specifically if new keys were added which cause modules to break.
def load_configuration(filename, *, filepath='dnx_system/data'):
    '''load json data from file, convert it to a python dict, then return as object.'''
    if (not filename.endswith('.json')):
        filename = str_join([filename, '.json'])

    # loading system default configs
    with open(f'{HOME_DIR}/{filepath}/{filename}', 'r') as system_settings:
        system_settings = json.load(system_settings)

    if os.path.exists(f'{HOME_DIR}/{filepath}/usr/{filename}'):

        # loading user configurations (if exists)
        with open(f'{HOME_DIR}/{filepath}/usr/{filename}', 'r') as usr_settings:
            usr_settings = json.load(usr_settings)

        # updating system settings dict with user settings to be used in memory/ by modules only.
        system_settings.update(usr_settings)

    return system_settings

def write_configuration(data, filename, *, filepath='dnx_system/data/usr'):
    '''write json data object to file.'''

    if (not filename.endswith('.json')):
        filename = str_join([filename, '.json'])

    with open(f'{HOME_DIR}/{filepath}/{filename}', 'w') as settings:
        json.dump(data, settings, indent=4)

def append_to_file(data, filename, *, filepath='dnx_system/data/usr'):
    '''append data to filepath..'''

    with open(f'{HOME_DIR}/{filepath}/{filename}', 'a') as settings:
        settings.write(data)

def tail_file(file, *, line_count):
    f = subprocess.run(['tail', '-n', f'{line_count}', file], capture_output=True)

    return list(reversed(f.stdout.decode().splitlines()))

def change_file_owner(file_path):
    if (os.getuid()):
        raise RuntimeError('process must be ran as root user to change file owner.')

    shutil.chown(file_path, user=USER, group=GROUP)
    os.chmod(file_path, 0o660)

def json_to_yaml(data, *, is_string=False):
    '''
    converts a string in json format or a dictionary into yaml syntax then returns as string. set "is_string" to True
    to skip over object serialization.
    '''

    if (not is_string):
        data = json.dumps(data, indent=4)

    str_replacement = ['{', '}', '"', ',']
    for s in str_replacement:
        data = data.replace(s, '')

    # removing empty lines and sliding indent back by 4 spaces
    return '\n'.join([y[4:] for y in data.splitlines() if y.strip()])

def load_dns_bitmap(Log, bl_exc=[], wl_exc=[]):
    dict_nets = defaultdict(list)
    blocked_file = f'{HOME_DIR}/dnx_system/signatures/domain_lists/blocked.domains'

    # converting blacklist exceptions (pre proxy) to be compatible with dnx signature syntax
    blacklist = [f'{domain} blacklist' for domain in bl_exc]

    with open(blocked_file, 'r') as sigs:
        for sig_set in [sigs, blacklist]:
            for sig in sig_set:
                try:
                    si = sig.strip().split(maxsplit=1)

                    host = si[0]
                    host_hash = f'{hash(si[0])}'
                    cat = int(DNS_CAT[si[1]])

                    b_id = int(host_hash[:DNS_BIN_OFFSET])
                    h_id = int(host_hash[DNS_BIN_OFFSET:])
                except Exception as E:
                    Log.warning(f'bad signature detected | {E} | {sig}')

                else:
                    # pre proxy override check before adding
                    if (host not in wl_exc):
                        dict_nets[b_id].append((h_id, cat))

        # in place sort of all containers prior to building the structure
        for containers in dict_nets.values():
            containers.sort()

    # converting to nested tuple and sorting, outermost list converted on return
    nets = [(bin_id, tuple(containers)) for bin_id, containers in dict_nets.items()]
    nets.sort()

    # no longer needed so ensuring memory gets freed
    del dict_nets

    return tuple(nets)

def load_tlds():
    dns_proxy = load_configuration('dns_proxy')

    for tld, setting in dns_proxy['tlds'].items():
        yield (tld.strip('.'), setting)

# function to load in all keywords corresponding to enabled domain categories. the try/except
# is used to ensure bad keywords do not prevent the proxy from starting, though the bad keyword
# will be omitted from the proxy.
def load_keywords(Log):
    '''returns keyword set for enabled domain categories'''

    keywords = []
    try:
        with open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/domain.keywords', 'r') as blocked_keywords:
            all_keywords = [
                x.strip() for x in blocked_keywords.readlines() if x.strip() and '#' not in x
            ]
    except FileNotFoundError:
        Log.critical('domain keywords file not found. contact support immediately.')

    else:
        for keyword_info in all_keywords:
            try:
                keyword, category = keyword_info.split(maxsplit=1)
            except:
                continue

            else:
                keywords.append((keyword, DNS_CAT[category]))

    return tuple(keywords)

def load_top_domains_filter():
    with open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/valid_top.domains', 'r') as tdf:
        return [s.strip() for s in tdf.readlines() if s.strip() and '#' not in s]

def calculate_file_hash(file_to_hash, *, path='dnx_system', folder='data'):
    '''returns the sha256 secure hash of the file sent in'''

    try:
        with open(f'{HOME_DIR}/{path}/{folder}/{file_to_hash}', 'rb') as f2h:
            file_hash = hashlib.sha256(f2h.read()).digest()

    except FileNotFoundError:
        return None

    return file_hash

def cfg_read_poller(watch_file, folder='data', class_method=False):
    '''Automate Class configuration file poll decorator. apply this decorator to all functions
    that will update configurations loaded in memory from json files. config file must be sent
    in via decorator argument. set class_method argument to true if being used with a class method.'''

    if not isinstance(watch_file, str):
        raise TypeError('watch file must be a string.')

    if (not watch_file.endswith('.json')):
        watch_file = str_join([watch_file, '.json'])

    def decorator(function_to_wrap):
        if (not class_method):
            def wrapper(*args):
                watcher = Watcher(watch_file, folder, callback=function_to_wrap)
                watcher.watch(*args)

        else:
            @classmethod
            def wrapper(*args):
                watcher = Watcher(watch_file, folder, callback=function_to_wrap)
                watcher.watch(*args)

        return wrapper
    return decorator

def cfg_write_poller(list_function):
    '''Automate class configuration file poll decorator. this decorator is only compatible with
    the dns proxy module whitelist/blacklist read/write operations'''

    def wrapper(*args):
        # print(f'[+] Starting user defined {args[1]} timer')
        last_modified_time, new_args = 0, (*args, f'{args[1]}.json')
        # main loop calling the primary function for read/write change detection/polling
        # the recycle the saved hash file which is returned regardless of if it was changed or not
        while True:
            last_modified_time = list_function(*new_args, last_modified_time)

            time.sleep(FILE_POLL_TIMER)
    return wrapper


class ConfigurationManager:
    '''
    Class to ensure process safe operations on configuration files. This class is written
    as a context manager and must be used as such. upon calling the context a file lock will
    be obtained or block until it can acquire the lock and return the class object to the caller.
    '''

    Log = None
    config_lock_file = f'{HOME_DIR}/dnx_system/config.lock'

    __slots__ = (
        '_config_lock', '_filename', '_data_written',
        '_file_path', '_system_path_file', '_usr_path_file',
        '_temp_file', '_temp_file_path', '_config_file',
    )

    @classmethod
    def set_log_reference(cls, ref):
        '''sets logging class reference for configuration manager specific errors.'''

        cls.Log = ref

    def __init__(self, config_file='', file_path=None):
        '''Config file can be omitted to allow for configuration lock to be used with
        external operations.'''

        self._config_file = config_file

        # initialization isn't required if config file is not specified.
        if (config_file):
            self._data_written = False

            if (not file_path):
                file_path = 'dnx_system/data'

            self._file_path = file_path

            # backwards compatibility between specifying file ext and not.
            self._filename = config_file if config_file.endswith('.json') else f'{config_file}.json'

            self._system_path_file = f'{HOME_DIR}/{file_path}/{self._filename}'
            self._usr_path_file = f'{HOME_DIR}/{file_path}/usr/{self._filename}'

        else:
            # make debug log complete if in lock only mode
            self._filename = 'ConfigurationManager'

    # attempts to acquire lock on system config lock (blocks until acquired), then opens a temporary
    # file which the new configuration will be written to, and finally returns the class object.
    def __enter__(self):
        self._config_lock = open(self.config_lock_file, 'r+')

        # acquiring lock on shared lock file
        flock(self._config_lock, LOCK_EX)

        # setup isn't required if config file is not specified.
        if (self._config_file):
            # TEMP prefix is to wildcard match any orphaned files for deletion
            self._temp_file_path = f'{HOME_DIR}/{self._file_path}/usr/TEMP_{token_urlsafe(10)}.json'
            self._temp_file = open(self._temp_file_path, 'w+')

            # changing file permissions and settings owner to dnx:dnx to not cause permissions issues after copy.
            os.chmod(self._temp_file_path, 0o660)
            shutil.chown(self._temp_file_path, user=USER, group=GROUP)

        self.Log.debug(f'Config file lock acquired for {self._filename}.')

        return self

    # if there is no exception on leaving the context and data was written to the temp file the temporary
    # file will be renamed over the configuration file sent in by the caller. if an exception is raised
    # the temporary file will be deleted. The file lock will be released upon exiting
    def __exit__(self, exc_type, exc_val, traceback):
        # lock only mode
        if (not self._config_file):
            pass

        elif (exc_type is None and self._data_written):
            os.replace(self._temp_file_path, self._usr_path_file)

        else:
            self._temp_file.close()
            os.unlink(self._temp_file_path)

        # releasing lock for purposes specified in flock(1) man page under -u (unlock)
        flock(self._config_lock, LOCK_UN)

        # closing file after unlock to allow reference to be cleaned up.
        self._config_lock.close()
        self.Log.debug(f'file lock released for {self._filename}')

        if (exc_type is None):
            return True

        elif (exc_type is not ValidationError):
            self.Log.error(f'configuration manager error: {exc_val}')

            raise OSError('Configuration manager was unable to update the requested file.')

    # will load json data from file, convert it to a python dict, then returned as object
    def load_configuration(self):
        '''returns python dictionary of configuration file contents'''

        if (not self._config_file):
            raise RuntimeError('Configuration Manager methods are disabled in lock only mode.')

        with open(self._system_path_file, 'r') as system_settings:
            system_settings = json.load(system_settings)

        if os.path.exists(self._usr_path_file):

            # loading user configurations (if exists)
            with open(self._usr_path_file, 'r') as usr_settings:
                usr_settings = json.load(usr_settings)

            # updating system settings dict with user settings to be used in memory/ by modules only.
            system_settings.update(usr_settings)

        return system_settings

    # accepts python dictionary to be serialized to json and written to file opened. will ensure
    # data gets fully rewritten and if short than original the excess gets truncated.
    def write_configuration(self, data_to_write):
        '''writes configuration data as json to generated temporary file'''

        if (not self._config_file):
            raise RuntimeError('Configuration Manager methods are disabled in lock only mode.')

        if (self._data_written):
            raise RuntimeWarning('configuration file has already been written to.')

        json.dump(data_to_write, self._temp_file, indent=4)
        self._temp_file.flush()

        # this is to inform context to copy temp file to dnx configuration folder
        self._data_written = True


class Watcher:
    '''this class is used to detect file changes, primarily configuration files.'''

    __slots__ = (
        '_watch_file', '_callback', '_full_path',
        '_last_modified_time'
    )

    def __init__(self, watch_file, folder, *, callback):
        self._watch_file = watch_file
        self._callback   = callback

        self._full_path = f'{HOME_DIR}/dnx_system/{folder}/usr/{watch_file}'

        self._last_modified_time = 0

    # will check file for change in set intervals, currently using global constant for config file polling
    def watch(self, *args):
        args = [*args, self._watch_file]

        while True:

            if (self.is_modified):
                self._callback(*args)

            else:
                time.sleep(FILE_POLL_TIMER)

    @property
    # if watch file has been modified will update modified time and return True, else return False
    def is_modified(self):
        if not os.path.isfile(self._full_path):

            # condition to allow initial load to happen without the usr file being present.
            # NOTE: the load configuration function used loads system defaults prior to user settings
            # so there will be no issue marking a non existent file as modified.
            if (not self._last_modified_time):
                self._last_modified_time = 1

                return True

            return False

        modified_time = os.stat(self._full_path).st_mtime
        if (modified_time != self._last_modified_time):

            # updating shared modified time to reflect recent changes and return True notifying system of
            # a file change event
            self._last_modified_time = modified_time

            return True

        return False
