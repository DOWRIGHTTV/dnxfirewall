#!/usr/bin/env python3

from __future__ import annotations

import os
import json
import time
import fcntl
import shutil
import hashlib
import subprocess

from copy import copy
from secrets import token_urlsafe
from collections import namedtuple

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import HOME_DIR, ROOT, USER, GROUP, RUN_FOREVER
from dnx_gentools.def_namedtuples import Item
from dnx_gentools.def_enums import DNS_CAT, DATA

from dnx_routines.configure.exceptions import ValidationError

FILE_POLL_TIMER = 10

file_exists = os.path.exists

# aliases for readability
FILE_LOCK = fcntl.flock
EXCLUSIVE_LOCK = fcntl.LOCK_EX
UNLOCK_LOCK = fcntl.LOCK_UN


def load_configuration(filename: str, ext: str = '.cfg', *, filepath: str = 'dnx_system/data') -> ConfigChain:
    '''load json data from a file and convert it to a ConfigChain.
    '''
    filename += ext

    # loading system default configs
    with open(f'{HOME_DIR}/{filepath}/{filename}', 'r') as system_settings_io:
        system_settings: dict = json.load(system_settings_io)

    # I like the path checks more than try/except block
    if not os.path.exists(f'{HOME_DIR}/{filepath}/usr/{filename}'):
        user_settings: dict = {}

    else:
        # loading user configurations
        with open(f'{HOME_DIR}/{filepath}/usr/{filename}', 'r') as user_settings_io:
            user_settings: dict = json.load(user_settings_io)

    return ConfigChain(system_settings, user_settings)

def write_configuration(data: dict, filename: str, ext: str = '.cfg', *, filepath: str = 'dnx_system/data/usr') -> None:
    '''write a json data object to file.
    '''
    filename += ext

    with open(f'{HOME_DIR}/{filepath}/{filename}', 'w') as settings:
        json.dump(data, settings, indent=4)

def load_data(filename: str, *, filepath: str = 'dnx_system/data') -> dict:
    '''loads json data from a file and convert it to a python dict.
    '''
    with open(f'{HOME_DIR}/{filepath}/{filename}', 'r') as system_settings_io:
        system_settings: dict = json.load(system_settings_io)

    return system_settings

# will load json data from file, convert it to a python dict, then return as an object
def write_data(data: dict, filename: str, *, filepath: str = 'dnx_system/data') -> None:

    with open(f'{HOME_DIR}/{filepath}/{filename}', 'w') as settings:
        json.dump(data, settings, indent=4)

def append_to_file(data: str, filename: str, *, filepath: str = 'dnx_system/data/usr') -> None:
    '''append data to filepath.
    '''
    with open(f'{HOME_DIR}/{filepath}/{filename}', 'a') as settings:
        settings.write(data)

def tail_file(file: str, *, line_count: int) -> list[str]:
    f = subprocess.run(['tail', '-n', f'{line_count}', file], capture_output=True, text=True)

    return list(reversed(f.stdout.splitlines()))

def change_file_owner(file_path: str) -> None:
    if (not ROOT):
        raise RuntimeError('process must be ran as root user to change file owner.')

    shutil.chown(file_path, user=USER, group=GROUP)
    os.chmod(file_path, 0o660)

def json_to_yaml(data: Union[str, dict], *, is_string: bool = False) -> str:
    '''
    converts a json string or dictionary into yaml syntax and returns as string.

    set "is_string" to True to skip over object serialization.
    '''
    if (not is_string):
        data = json.dumps(data, indent=4)

    str_replacement = ['{', '}', '"', ',']
    for s in str_replacement:
        data = data.replace(s, '')

    # removing empty lines and sliding indent back by 4 spaces
    return '\n'.join([y[4:] for y in data.splitlines() if y.strip()])

def load_tlds() -> Generator[tuple[str, int]]:
    dns_proxy: ConfigChain = load_configuration('dns_proxy')

    for tld, setting in dns_proxy.get_items('tlds'):
        yield (tld.strip('.'), setting)

# function to load in all keywords corresponding to enabled domain categories. the try/except
# is used to ensure bad keywords do not prevent the proxy from starting, though the bad keyword
# will be omitted from the proxy.
def load_keywords(log: LogHandler_T) -> tuple[tuple[str, DNS_CAT]]:
    '''returns keyword set for enabled domain categories.
    '''
    keywords: list[tuple[str, DNS_CAT]] = []
    try:
        with open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/domain.keywords', 'r') as blocked_keywords:
            all_keywords = [
                x.strip() for x in blocked_keywords.readlines() if x.strip() and '#' not in x
            ]
    except FileNotFoundError:
        log.critical('domain keywords file not found.')

    else:
        for keyword_info in all_keywords:
            try:
                keyword, category = keyword_info.split(maxsplit=1)
            except:
                continue

            else:
                keywords.append((keyword, DNS_CAT[category]))

    return tuple(keywords)

def load_top_domains_filter() -> list[str]:
    with open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/valid_top.domains', 'r') as tdf:
        return [s.strip() for s in tdf.readlines() if s.strip() and '#' not in s]

def calculate_file_hash(file_to_hash: str, *, path: str = 'dnx_system', folder: str = 'data') -> Optional[str]:
    '''returns the sha256 secure hash of passed in file.'''

    filepath = f'{HOME_DIR}/{path}/{folder}/{file_to_hash}'
    if not os.path.exists(filepath):
        return None

    with open(filepath, 'rb') as f2h:
        file_hash = hashlib.sha256(f2h.read()).hexdigest()

    return file_hash

def cfg_read_poller(watch_file: str, ext: bool = True, *, folder: str = 'data', class_method: bool = False):
    '''Automate Class configuration file poll decorator.

    apply this decorator to all functions that will update configurations loaded in memory from json files.
    config file must be sent in via decorator argument. set class_method argument to true if being used with a
    class method.'''

    if not isinstance(watch_file, str):
        raise TypeError('watch file must be a string.')

    if (not ext):
        watch_file += '.cfg'

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

def cfg_write_poller(list_function: DNSListHandler) -> Wrapper:
    '''Automate class configuration file poll decorator. this decorator is only compatible with
    the dns proxy module whitelist/blacklist read/write operations'''

    def wrapper(*args):
        # print(f'[+] Starting user defined {args[1]} timer')
        last_modified_time, new_args = 0, (*args, f'{args[1]}.cfg')
        # main loop calling the primary function for read/write change detection/polling
        # the recycle the saved hash file which is returned regardless of if it was changed or not
        for _ in RUN_FOREVER:
            last_modified_time = list_function(*new_args, last_modified_time)

            time.sleep(FILE_POLL_TIMER)
    return wrapper

class config(dict):

    def __init__(self, **kwargs: dict[str, Union[str, int, bool]]):
        super().__init__()

        for k, v in kwargs.items():
            self[k] = v

    def __getattr__(self, item: str) -> Any:
        return self[item]

    def __setattr__(self, key: str, value: Union[str, int, bool]):
        self[key] = value


class ConfigChain:

    _sep: ClassVar[str] = '->'

    __slots__ = (
        '__config', '__flat_config', '__mutable_config'
    )

    def __init__(self, system: dict, user: dict):

        self.__config = (user, system)
        self.__flat_config = (
            self._flatten(user), self._flatten(system)
        )

        self.__mutable_config = copy(self.__flat_config[0])

    def __getitem__(self, key: str) -> Optional[Union[bool, int, str, list]]:

        for cfg in self.__flat_config:

            value = cfg.get(key, DATA.MISSING)
            if (value is not DATA.MISSING):
                return value

        raise KeyError(f'{key} not found in configuration chain.')

    def __setitem__(self, key: str, value: Union[bool, int, str, list, None]):

        # print('setting ->', value)

        self.__mutable_config[key] = value

    def __delitem__(self, key: str) -> None:

        key_matches = [k for k in self.__mutable_config if k.startswith(key)]
        for k in key_matches:
            del self.__mutable_config[k]

    def get(self, key: str, ret_val: Any = None) -> Any:

        for cfg in self.__flat_config:

            value = cfg.get(key, DATA.MISSING)
            if (value is not DATA.MISSING):
                return value

        return ret_val

    def get_dict(self, key: Optional[str] = None) -> dict[str, Any]:
        '''return dict of children 1 level lower than the passed in key.

         returns an empty dict if not found.

            config.get_dict('interfaces->builtins')
        '''
        keys = [] if key is None else key.split(self._sep)
        search_data = self._merge_expand()

        for k in keys:
            try:
                search_data = search_data[k]
            except KeyError:
                return {}

        return search_data

    def get_list(self, key: Optional[str] = None) -> list[str]:
        '''return list of child keys 1 level lower than the passed in key.

        returns an empty list if not found.

            config.get_list('interfaces->builtins')
        '''
        keys = [] if key is None else key.split(self._sep)
        search_data = self._merge_expand()

        for k in keys:
            try:
                search_data = search_data[k]
            except KeyError:
                return []

        return list(search_data)

    def get_items(self, key: Optional[str] = None) -> list[Optional[Item]]:
        '''return list of namedtuple containing key: value pairs of child keys 1 level lower than the passed in key.

        returns an empty list if not found.

            config.get_items('interfaces->builtins')
        '''
        keys = [] if key is None else key.split(self._sep)
        search_data = self._merge_expand()

        for k in keys:
            try:
                search_data = search_data[k]
            except KeyError:
                return []

        return [Item(k, v) for k, v in search_data.items()]

    def get_values(self, key: Optional[str] = None) -> list:
        '''return a list of values for the child keys 1 level lower than the passed in key.

        returns an empty list if not found.

            config.get_items('interfaces->builtins')
        '''
        keys = [] if key is None else key.split(self._sep)
        search_data = self._merge_expand()

        for k in keys:
            try:
                search_data = search_data[k]
            except KeyError:
                return []

        return list(search_data.values())

    @property
    def searchable_system_data(self) -> dict:
        '''returns copy of original pre-flattened system config dictionary.
        '''
        return copy(self.__config[1])

    @property
    def searchable_user_data(self) -> dict:
        '''returns copy of original pre-flattened user config dictionary.
        '''
        return copy(self.__config[0])

    @property
    def user_data(self) -> dict:
        '''returns mutable flattened user config dictionary.
        '''
        return self.__mutable_config

    @property
    def expanded_user_data(self) -> dict:
        '''returns snapshot of expanded user config dictionary.

        additional calls are required to reflect changes to user data outside the returned object.
        '''
        return self._expand(self.__mutable_config)

    def _merge_expand(self) -> dict:
        '''overloads system config with user data then expands and returns dictionary.
        '''
        combined_config = copy(self.__flat_config[1])

        combined_config.update(self.__flat_config[0])

        return self._expand(combined_config)

    def _flatten(self, cfg: dict, /, parent_key: str = '') -> dict:
        flat_d = {}
        for key, value in cfg.items():

            # > 1st level
            if (parent_key):
                key = f'{parent_key}{self._sep}{key}'

            # not a dict or empty dict
            if not isinstance(value, dict) or not value:
                flat_d[key] = value

            else:
                flat_d = {**flat_d, **self._flatten(value, key)}

        return flat_d

    def _expand(self, cfg: dict, /) -> dict:
        expand_d = {}

        for key, value in cfg.items():

            key_path = key.split(self._sep)
            nested = expand_d

            for nkey in key_path[:-1]:
                try:
                    nested = nested[nkey]
                except KeyError:
                    nested[nkey] = nested = {}

            nested[key_path[-1]] = value

        return expand_d


class ConfigurationManager:
    '''
    Class to ensure process safe operations on configuration files.

    This class is written as a context manager and must be used as such. upon calling the context, a file lock will be
    obtained or block until it can acquire the lock and return the class object to the caller.
    '''
    log: ClassVar[LogHandler_T] = None
    config_lock_file: ClassVar[ConfigLock] = f'{HOME_DIR}/dnx_system/config.lock'

    __slots__ = (
        '_config_lock', '_filename', '_data_written',
        '_file_path', '_system_path_file', '_usr_path_file',
        '_temp_file', '_temp_file_path', '_config_file',
    )

    @classmethod
    def set_log_reference(cls, ref: LogHandler_T) -> None:
        '''sets logging class reference for configuration manager specific errors.
        '''
        cls.log = ref

    def __init__(self, config_file: str = '', ext: str = '.cfg', file_path: Optional[str] = None) -> None:
        '''config_file can be omitted to allow for configuration lock to be used with
        external operations.
        '''
        self._config_file = config_file

        # initialization isn't required if config file is not specified.
        if (not config_file):
            # make debug log complete if in lock only mode
            self._filename = 'ConfigurationManager'

        else:
            self._data_written = False

            if (not file_path):
                file_path = 'dnx_system/data'

            self._file_path = file_path
            self._filename = config_file + ext

            self._system_path_file = f'{HOME_DIR}/{file_path}/{self._filename}'
            self._usr_path_file = f'{HOME_DIR}/{file_path}/usr/{self._filename}'

    # attempts to acquire lock on system config lock (blocks until acquired), then opens a temporary
    # file which the new configuration will be written to, and finally returns the class object.
    def __enter__(self) -> ConfigurationManager:
        self._config_lock = open(self.config_lock_file, 'r+')

        # acquiring lock on shared lock file
        FILE_LOCK(self._config_lock, EXCLUSIVE_LOCK)

        # setup isn't required if config file is not specified.
        if (self._config_file):
            # TEMP prefix is to wildcard match any orphaned files for deletion
            self._temp_file_path = f'{HOME_DIR}/{self._file_path}/usr/TEMP_{token_urlsafe(10)}'
            self._temp_file = open(self._temp_file_path, 'w+')

            # changing file permissions and settings owner to dnx:dnx to not cause permission issues after copy.
            os.chmod(self._temp_file_path, 0o660)
            shutil.chown(self._temp_file_path, user=USER, group=GROUP)

        self.log.debug(f'Config file lock acquired for {self._filename}.')

        return self

    # if no exception was raised and data was written, the temporary file will be replaced over the designated
    # configuration file. if an exception is raised, the temporary file will be deleted. the file lock will be released
    # upon exiting
    def __exit__(self, exc_type, exc_val, traceback) -> bool:
        # lock only mode
        if (not self._config_file):
            pass

        elif (exc_type is None and self._data_written):
            os.replace(self._temp_file_path, self._usr_path_file)

        else:
            self._temp_file.close()
            os.unlink(self._temp_file_path)

        # releasing lock for purposes specified in flock(1) man page under -u (unlock)
        FILE_LOCK(self._config_lock, UNLOCK_LOCK)

        # closing file after unlock to allow reference to be cleaned up.
        self._config_lock.close()
        self.log.debug(f'file lock released for {self._filename}')

        if (exc_type is None):
            return True

        elif (exc_type is not ValidationError):
            self.log.error(f'configuration manager error: {exc_val}')

            raise OSError('Configuration manager was unable to update the requested file.')

    # will load json data from file, convert it to a ConfigChain
    def load_configuration(self) -> ConfigChain:
        '''returns python dictionary of configuration file contents.
        '''
        if (not self._config_file):
            raise RuntimeError('Configuration Manager methods are disabled in lock only mode.')

        return load_configuration(self._filename, ext='', filepath=self._file_path)

    # accepts python dictionary for serialization to json. writes data to specified file opened.
    def write_configuration(self, data_to_write: dict):
        '''writes configuration data as json to generated temporary file.
        '''
        if (not self._config_file):
            raise RuntimeError('Configuration Manager methods are disabled in lock only mode.')

        if (self._data_written):
            raise RuntimeWarning('configuration file has already been written to.')

        json.dump(data_to_write, self._temp_file, indent=4)
        self._temp_file.flush()

        # this is to inform context to copy temp file to dnx configuration folder
        self._data_written = True


class Watcher:
    '''Class for detecting file changes within the dnxfirewall filesystem.

     primary use is to detect when a configuration file has been changed by an administrator.
     '''
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
    def watch(self, *args) -> None:
        args = [*args, self._watch_file]

        for _ in RUN_FOREVER:

            if (self.is_modified):
                self._callback(*args)

            else:
                time.sleep(FILE_POLL_TIMER)

    @property
    # if watch file has been modified, update the modified time and return True, else return False
    def is_modified(self) -> bool:
        if not os.path.isfile(self._full_path):

            # condition to allow the initial load to happen without the usr file being present.
            # NOTE: the load configuration function loads system defaults prior to user settings
            # so there will be no issue marking a non-existent file as modified.
            if (not self._last_modified_time):
                self._last_modified_time = 1

                return True

            return False

        modified_time = os.stat(self._full_path).st_mtime
        if (modified_time != self._last_modified_time):

            # updating shared modified time to reflect recent changes and return True notifying the system of
            # a file change event
            self._last_modified_time = modified_time

            return True

        return False
