#!/usr/bin/env python3

from __future__ import annotations

import os
import json
import fcntl
import shutil
import hashlib
import subprocess

from copy import copy
from functools import wraps
from secrets import token_urlsafe

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import HOME_DIR, ROOT, USER, GROUP, RUN_FOREVER, fast_sleep
from dnx_gentools.def_namedtuples import Item
from dnx_gentools.def_enums import DNS_CAT, DATA
from dnx_gentools.def_exceptions import ConfigurationError, ControlError

from dnx_webui.source.web_validate import ValidationError

# ================
# TYPING IMPORTS
# ================
if (TYPE_CHECKING):
    from dnx_routines.logging import LogHandler_T


__all__ = (
    'acquire_lock', 'release_lock',
    'load_configuration', 'write_configuration',
    'load_data', 'write_data',
    'append_to_file', 'tail_file', 'change_file_owner',
    'json_to_yaml',
    'load_tlds', 'load_keywords', 'load_top_domains_filter',
    'calculate_file_hash',
    'cfg_read_poller', 'cfg_write_poller', 'Watcher',

    'config', 'ConfigChain', 'ConfigurationManager'
)

FILE_POLL_TIMER = 10

file_exists = os.path.exists

sha256 = hashlib.sha256

# aliases for readability
ACQUIRE_LOCK: Callable[[TextIO], None] = lambda mutex: fcntl.flock(mutex, fcntl.LOCK_EX)
RELEASE_LOCK: Callable[[TextIO], None] = lambda mutex: fcntl.flock(mutex, fcntl.LOCK_UN)

def acquire_lock(file: str) -> TextIO:
    '''opens passed in filepath and acquires a file lock.

    the file object is returned.
    '''
    mutex = open(file)

    ACQUIRE_LOCK(mutex)

    return mutex

def release_lock(mutex: TextIO):
    '''releases file lock on the passed in file object.

    the file object will be closed.
    '''
    RELEASE_LOCK(mutex)

    mutex.close()

def load_configuration(
        filename: str, ext: str = 'cfg', *,
        cfg_type: str = '', filepath: str = 'dnx_profile/data', strict: bool = True) -> ConfigChain:
    '''load json data from a file and convert it to a ConfigChain.

        strict mode will conform usr config to system config.
        non-conforming keys will be removed from the ConfigChain.
    '''
    user_filename = f'{cfg_type}/{filename}.{ext}' if cfg_type else f'{filename}.{ext}'

    # note: quick parse for detecting if the configuration file is a profile, then set the system default accordingly.
    # a profile will always have a cfg_type (i think) so dont need the logic for it not being present.
    system_filename = f'{cfg_type}/profiles/profile_0.cfg' if filename.split('/')[0] == 'profiles' else user_filename

    # loading system default configs
    with open(f'{HOME_DIR}/{filepath}/system/{system_filename}', 'r') as system_settings_io:
        system_settings: dict = json.load(system_settings_io)

    # I like the path checks more than try/except block
    if not file_exists(f'{HOME_DIR}/{filepath}/usr/{user_filename}'):
        user_settings: dict = {}

    else:
        # loading user configurations
        with open(f'{HOME_DIR}/{filepath}/usr/{user_filename}', 'r') as user_settings_io:
            user_settings: dict = json.load(user_settings_io)

    return ConfigChain(system_settings, user_settings, strict)

def write_configuration(
        data: dict, filename: str, ext: str = 'cfg', *, cfg_type: str = '', filepath: str = 'dnx_profile/data/usr') -> None:
    '''write a json data object to file.
    '''
    filename = f'{cfg_type}/{filename}.{ext}' if cfg_type else f'{filename}.{ext}'

    with open(f'{HOME_DIR}/{filepath}/{filename}', 'w') as settings:
        json.dump(data, settings, indent=2)

def load_data(filename: str, *, cfg_type: str = '', filepath: str = 'dnx_profile/data') -> dict:
    '''loads json data from a file and convert it to a python dict.

    - does not provide a default file extension.
    - does not check if the file exists before attempting to open it.
    '''
    filename = f'{cfg_type}/{filename}' if cfg_type else f'{filename}'

    with open(f'{HOME_DIR}/{filepath}/{filename}', 'r') as system_settings_io:
        system_settings: dict = json.load(system_settings_io)

    return system_settings

def write_data(data: dict, filename: str, *, cfg_type: str = '', filepath: str = 'dnx_profile/data') -> None:
    '''write json data to a file from a python dict.

    this function does not provide a default file extension.
    '''
    filename = f'{cfg_type}/{filename}' if cfg_type else f'{filename}'

    with open(f'{HOME_DIR}/{filepath}/{filename}', 'w') as settings:
        json.dump(data, settings, indent=2)

def append_to_file(data: str, filename: str, *, filepath: str = 'dnx_profile/data/usr') -> None:
    '''append data to filepath. NOTE: needs to be refactored to new folder structure.
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
    proxy_config: ConfigChain = load_configuration('profiles/profile_1', cfg_type='security/dns')

    for tld, setting in proxy_config.get_items('tld'):
        yield (tld.strip('.'), setting)

# TODO: this needs to be reworked to support the new keyword matching system.
def load_keywords(log: LogHandler_T) -> list[tuple[str, DNS_CAT]]:
    '''returns keyword set for enabled domain categories.

    malformed keywords will be omitted.
    '''
    keywords: list[tuple[str, DNS_CAT]] = []
    try:
        with open(f'{HOME_DIR}/dnx_profile/signatures/domain_lists/domain.keywords', 'r') as blocked_keywords:
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

    return keywords

def load_top_domains_filter() -> list[str]:
    with open(f'{HOME_DIR}/dnx_profile/signatures/domain_lists/valid_top.domains', 'r') as tdf:
        return [s.strip() for s in tdf.readlines() if s.strip() and '#' not in s]

def calculate_file_hash(
        file_to_hash: str, *, path: str = 'dnx_profile', folder: str = 'data', full_path: bool = False) -> str:
    '''returns the sha256 secure hash of passed in file.

    if full_path is True then the file_to_hash argument will be used as is.
    '''
    filepath = file_to_hash if full_path else f'{HOME_DIR}/{path}/{folder}/{file_to_hash}'
    if not file_exists(filepath):
        return ''

    with open(filepath, 'rb') as f2h:
        file_hash = sha256(f2h.read()).hexdigest()

    return file_hash

def cfg_read_poller(
        watch_file: str, *, ext: str = 'cfg', cfg_type: str = '', filepath: str = 'dnx_profile/data', class_method: bool = False):
    '''Automate Class configuration file poll decorator.

    apply this decorator to all functions that will update configurations loaded in memory from json files.
    config file must be sent in via decorator argument.
    set class_method argument to true if being used with a class method.

    extension will not be added to watch file automatically.
    '''
    if not isinstance(watch_file, str):
        raise TypeError('watch file must be a string.')

    def decorator(function_to_wrap):
        @wraps(function_to_wrap)
        def wrapper(*args):
            watcher = Watcher(watch_file, ext, cfg_type, filepath, callback=function_to_wrap)
            watcher.watch(*args)

        if (class_method):
            wrapper = classmethod(wrapper)

        return wrapper
    return decorator

def cfg_write_poller(list_function: DNSListHandler) -> Wrapper:
    '''Automate module configuration class file polling for read and writes.

    only compatible with the dns proxy module whitelist/blacklist read/write operations.
    '''
    @wraps(list_function)
    def wrapper(*args):
        # print(f'[+] Starting user defined {args[1]} timer')
        last_modified_time, new_args = 0, (*args, args[1])
        # main loop calling the primary function for read/write change detection/polling
        # the recycle the saved hash file which is returned regardless of whether it was changed or not
        for _ in RUN_FOREVER:
            last_modified_time = list_function(*new_args, last_modified_time)

            fast_sleep(FILE_POLL_TIMER)
    return wrapper

class config(dict):

    def __init__(self, **kwargs: dict[str, Union[str, int, bool]]):
        super().__init__()

        for k, v in kwargs.items():
            self[k] = v

    def __getattr__(self, item: str) -> Any:
        '''calls __getitem__ and returns the returned value.

        raises AttributeError on error.
        '''
        try:
            return self[item]
        except KeyError:
            raise AttributeError

    def __setattr__(self, key: str, value: Union[str, int, bool]):
        self[key] = value


# TODO: shouldnt __mutable_config be an alias to __flatten_config[0] (user config) so any changes to the data will be
#  reflected in the _merge_expand operation and subsequently all the get methods.
class ConfigChain:

    _sep: ClassVar[str] = '->'

    __slots__ = (
        '__config', '__flat_config', '__mutable_config'
    )

    def __init__(self, system: dict, user: dict, strict: bool):

        system_flat = self._flatten(system)
        user_flat = {k: v for k, v in self._flatten(user).items() if k in system_flat} if strict else self._flatten(user)

        self.__config = (user, system)
        self.__flat_config = (user_flat, system_flat)

        self.__mutable_config = copy(self.__flat_config[0])

    def __str__(self):
        return json.dumps(self._merge_expand(), indent=2)

    def __getitem__(self, key: str) -> Union[bool, int, str, list]:

        for cfg in self.__flat_config:

            value = cfg.get(key, DATA.MISSING)
            if (value is not DATA.MISSING):
                return value

        raise KeyError(f'{key} not found in configuration chain.')

    def __setitem__(self, key: str, value: Union[bool, int, float, str, list, None]):

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

    def get_dict(self, key: str = None) -> dict[str, Any]:
        '''return dict of children 1 level lower than the passed in key.

         returns an empty dict if not found.

            config.get_dict('interfaces->builtin')
        '''
        keys = [] if key is None else key.split(self._sep)
        search_data = self._merge_expand()

        for k in keys:
            try:
                search_data = search_data[k]
            except KeyError:
                return {}

        return search_data

    def get_list(self, key: str = None) -> list[Union[str, int]]:
        '''return list of child keys 1 level lower than the passed in key.

        returns an empty list if not found.

            config.get_list('interfaces->builtin')
        '''
        keys = [] if key is None else key.split(self._sep)
        search_data = self._merge_expand()

        for k in keys:
            try:
                search_data = search_data[k]
            except KeyError:
                return []

        return list(search_data)

    def get_items(self, key: str = None) -> list[Item]:
        '''return list of namedtuple containing key: value pairs of child keys 1 level lower than the passed in key.

        returns an empty list if not found.

            config.get_items('interfaces->builtin')
        '''
        keys = [] if key is None else key.split(self._sep)
        search_data = self._merge_expand()

        for k in keys:
            try:
                search_data = search_data[k]
            except KeyError:
                return []

        return [Item(k, v) for k, v in search_data.items()]

    def get_values(self, key: str = None) -> list:
        '''return a list of values for the child keys 1 level lower than the passed in key.

        returns an empty list if not found.

            config.get_values('interfaces->builtin')
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
    '''Class to ensure process safe operations on configuration files.

    This class is written as a context manager and must be used as such. upon calling the context, a file lock will be
    obtained or block until it can acquire the lock and return the class object to the caller.
    '''
    log: LogHandler_T = None
    config_lock_file: ConfigLock = f'{HOME_DIR}/dnx_profile/data/config.lock'

    __slots__ = (
        '_name', '_ext', '_cfg_type', '_filename',

        '_config_lock', '_data_written',
        '_file_path', '_usr_path_file',  # '_system_path_file',
        '_temp_file', '_temp_file_path',
    )

    @classmethod
    def set_log_reference(cls, ref: LogHandler_T) -> None:
        '''sets logging class reference for configuration manager specific errors.
        '''
        cls.log: LogHandler_T = ref

    def __init__(self, name: str = '', ext: str = 'cfg', cfg_type: str = '', file_path: str = None) -> None:
        '''config_file can be omitted to allow for configuration lock to be used with
        external operations.
        '''
        self._name = name
        self._ext  = ext
        self._cfg_type = cfg_type

        # initialization isn't required if config file is not specified.
        if (not name):
            # make debug log complete if in lock only mode
            self._filename = 'ConfigurationManager'

        else:
            self._data_written = False

            if (not file_path):
                file_path = 'dnx_profile/data'

            self._file_path = file_path
            self._filename = f'{cfg_type}/{name}.{ext}' if cfg_type else f'{name}.{ext}'

            # self._system_path_file = f'{HOME_DIR}/{file_path}/system/{self._filename}'
            self._usr_path_file = f'{HOME_DIR}/{file_path}/usr/{self._filename}'

    # attempts to acquire lock on system config lock (blocks until acquired), then opens a temporary
    # file which the new configuration will be written to, and finally returns the class object.
    def __enter__(self) -> ConfigurationManager:
        self._config_lock = acquire_lock(self.config_lock_file)

        # setup required only if the config file is specified.
        if (self._name):
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
        if (not self._name):
            pass

        elif (exc_type is None and self._data_written):
            os.replace(self._temp_file_path, self._usr_path_file)

        else:
            self._temp_file.close()
            os.unlink(self._temp_file_path)

        # releasing lock for purposes specified in flock(1) man page under -u (unlock)
        RELEASE_LOCK(self._config_lock)

        # closing the file after unlocking to allow reference to be cleaned up.
        self._config_lock.close()
        self.log.debug(f'file lock released for {self._filename}')

        if (exc_type is None):
            return True

        if (exc_type is ControlError):
            raise

        elif (exc_type is not ValidationError):
            self.log.error(f'ConfigurationManager: {exc_val}')

            raise ConfigurationError(f'Configuration manager failed while updating file. error->{exc_val}')

    # will load json data from file, convert it to a ConfigChain
    def load_configuration(self, *, strict: bool = True) -> ConfigChain:
        '''returns python dictionary of configuration file contents.
        '''
        if (not self._name):
            raise RuntimeError('Configuration Manager methods are disabled in lock only mode.')

        return load_configuration(
            self._name, self._ext, cfg_type=self._cfg_type, filepath=self._file_path, strict=strict)

    # accepts python dictionary for serialization to json. writes data to specified file opened.
    def write_configuration(self, data_to_write: dict):
        '''writes configuration data as json to generated temporary file.
        '''
        if (not self._name):
            raise RuntimeError('Configuration Manager methods are disabled in lock only mode.')

        if (self._data_written):
            raise RuntimeWarning('configuration file has already been written to.')

        json.dump(data_to_write, self._temp_file, indent=2)
        self._temp_file.flush()

        # this is to inform context to copy temp file to dnx configuration folder
        self._data_written = True


class Watcher:
    '''Class for detecting file changes within the dnxfirewall filesystem.

     primary use is to detect when an administrator has changed a configuration file.
     '''
    __slots__ = (
        '_watch_file', '_ext', '_cfg_type', '_filepath', '_callback', '_full_path',
        '_last_modified_time'
    )

    def __init__(self, watch_file: str, ext: str, cfg_type: str, filepath: str, *, callback: Callable_T):
        self._watch_file = watch_file

        self._ext      = ext
        self._cfg_type = cfg_type
        self._filepath = filepath

        self._callback = callback

        self._full_path = f'{HOME_DIR}/{filepath}/usr/{cfg_type}/{watch_file}.{ext}'

        self._last_modified_time = 0

    def watch(self, *args) -> None:
        '''check the configuration file for changes in set intervals.
        currently using global constant for config file polling.

        if a change is detected in the polled file, the file will be loaded as a ConfigChain and passed to the set
        callback function.
        '''
        for _ in RUN_FOREVER:

            if (self.is_modified):
                config_chain: ConfigChain = load_configuration(
                    self._watch_file, self._ext, cfg_type=self._cfg_type, filepath=self._filepath, strict=False)

                self._callback(*args, config_chain)

            else:
                fast_sleep(FILE_POLL_TIMER)

    @property
    # if watch file has been modified, update the modified time and return True, else return False
    def is_modified(self) -> bool:
        if not file_exists(self._full_path):

            # condition to allow the initial load to happen without the usr file being present.
            # NOTE: the load configuration function loads system defaults prior to user settings
            #  so there will be no issue marking a non-existent file as modified.
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
