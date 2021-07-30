#!/usr/bin/env python3

import os, sys
import json
import time
import shutil
import hashlib
import subprocess

from fcntl import flock, LOCK_EX, LOCK_UN
from secrets import token_urlsafe
from collections import defaultdict
from ipaddress import IPv4Address, IPv4Network

HOME_DIR = os.environ['HOME_DIR']
sys.path.insert(0, HOME_DIR)

from dnx_configure.dnx_constants import USER, GROUP, LOG, FILE_POLL_TIMER, str_join
from dnx_configure.dnx_constants import DNS_BIN_OFFSET, DNS_CAT, IPP_CAT, GEO
from dnx_configure.dnx_exceptions import ValidationError

# definitions for ip proxy data structures. Consider moving to constants module (make name more specific)
MSB = 0b11111111111110000000000000000000
LSB = 0b00000000000001111111111111111111

# will load json data from file, convert it to a python dict, then return as object
# TODO: add usr config support, which will merge will loaded system defaults.
def load_configuration(filename, *, filepath='/dnx_system/data'):
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

# TODO: write configs to usr folder keeping main system configs as defaults.
def write_configuration(data, filename, *, filepath='/dnx_system/data/usr'):
    '''write json data object to file.'''

    if (not filename.endswith('.json')):
        filename = str_join([filename, '.json'])

    with open(f'{HOME_DIR}/{filepath}/{filename}', 'w') as settings:
        json.dump(data, settings, indent=4)

def append_to_file(data, filename, *, filepath='/dnx_system/data/usr'):
    '''append data to filepath..'''

    with open(f'{HOME_DIR}/{filepath}/{filename}', 'a') as settings:
        settings.write(data)

def tail_file(file, *, line_count):
    f = subprocess.run(['tail', '-n', f'{line_count}', file], capture_output=True)

    return reversed(f.stdout.decode().splitlines())

def change_file_owner(file_path):
    if (os.getuid()):
        raise RuntimeError('process must be ran as root user to change file owner.')

    shutil.chown(file_path, user=USER, group=GROUP)
    os.chmod(file_path, 0o660)

def json_to_yaml(data, *, is_string=False):
    '''converts a string in json format or a dictionary into yaml syntax then returns as string. set "is_string" to True
    to skip over object serialization.
    '''

    if (not is_string):
        data = json.dumps(data)

    str_replacement = ['{', '}', '"', ',']

    data = data.replace('    ', '', 1)
    for s in str_replacement:
        data = data.replace(s, '')

    return '\n'.join([y for y in data.splitlines() if y.strip()])

# used to load ip and domain signatures. if whitelist exceptions are specified then they will not
# get loaded into the proxy. the try/except block is used to ensure bad rules dont prevent proxy
# from starting though the bad rule will be ommited from the proxy.
def load_signatures(Log, *, mod, exc=[]):
    signatures = {}
    with open(f'{HOME_DIR}/dnx_system/signatures/{mod}_lists/blocked.{mod}s', 'r') as blocked_sigs:
        for signature in blocked_sigs:
            try:
                host_signature = signature.strip().split(maxsplit=1)
                host, category = host_signature
            except:
                Log.warning(f'bad signature detected in {mod}.')
            else:
                if (host not in exc):
                    signatures[host] = category

        return signatures

def load_dns_bitmap(Log, bl_exc=[], wl_exc=[]):
    dict_nets = {}
    # converting blacklist exceptions (pre proxy) to be compatible with dnx signature syntax
    blacklist = [f'{domain} blacklist' for domain in bl_exc]

    with open(f'{HOME_DIR}/dnx_system/signatures/domain_lists/blocked.domains', 'r') as sigs:
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
                    print(f'bad signature detected in domain. | {E} | {sig}')
                else:
                    if (host in wl_exc): continue # overriding signature pre proxy
                    try:
                        dict_nets[b_id].append((h_id, cat))
                    except Exception as E:
                        dict_nets[b_id] = [(h_id, cat)]
                    else:
                        dict_nets[b_id].sort()

    # converting to nested tuple and sorting, list > tuple done on return
    nets = [(k, tuple(v)) for k,v in dict_nets.items()]
    nets.sort()

    dict_nets = None

    return tuple(nets)

def load_ip_bitmap(Log):
    '''returns a bitmap trie for ip host filtering loaded from the consolodated blocked.ips file.'''
    dict_nets = defaultdict(list)
    with open(f'{HOME_DIR}/dnx_system/signatures/ip_lists/blocked.ips', 'r') as ip_sigs:
        for signature in ip_sigs:

            # preventing disabled signatures from being loaded
            if signature.startswith('#'): continue

            sig = signature.strip().split(maxsplit=1)
            try:
                ip_addr = int(IPv4Address(sig[0]))
                cat = int(IPP_CAT[sig[1].upper()])
            except Exception as E:
                Log.warning(f'bad signature detected in ip. | {E} | {signature}')
                continue

            bin_id  = ip_addr & MSB
            host_id = ip_addr & LSB

            dict_nets[bin_id].append((host_id, cat))

            # NOTE: sorting items in the current bin. This could be moved to the end if we did a final
            # iter pass over the dict_nets to sort. This would also prevent having to sort more times than needed.
            dict_nets[bin_id].sort()

    # converting to nested tuple and sorting, list > tuple done on return
    nets = [(k, tuple(v)) for k,v in dict_nets.items()]
    nets.sort()

    dict_nets = None

    return tuple(nets)

# being deprecated for new signature operations function.
def load_geo_bitmap(Log):
    '''returns a bitmap trie for geolocation filtering loaded from the consolodated blocked.geo file.'''

    raise DeprecationWarning('this function is being replaced by the signature operations module.')

    # temporary dict to generate dataset easier and local var for easier bin size adjustments
    dict_nets = defaultdict(list)
    with open(f'{HOME_DIR}/dnx_system/signatures/geo_lists/blocked.geo', 'r') as geo_sigs:
        geo_sigs = list(geo_sigs)

    for net in geo_sigs:

        # preventing disabled signatures from being loaded
        if net.startswith('#'): continue

        geo_signature = net.strip().split(maxsplit=1)
        try:
            net, country = IPv4Network(geo_signature[0]), int(GEO[geo_signature[1].upper()])
        except Exception as E:
            Log.warning(f'bad signature detected in geo. | {E} | {net}')
            continue

        # assigning vars for bin id, host ranges, and ip count
        net_id = int(net.network_address)
        ip_count = int(net.num_addresses) - 1
        if (ip_count < LSB):
            bin_id = net_id & MSB
            host_id_start = net_id & LSB

            dict_nets[bin_id].append(
                (host_id_start, host_id_start+ip_count, country)
            )

        else:
            offset = 0
            while True:
                current_ip_index = int(net[offset])
                bin_id = current_ip_index & MSB

                remaining_ips = ip_count - offset
                if (remaining_ips <= LSB):
                    dict_nets[bin_id].append(
                        (current_ip_index, current_ip_index+remaining_ips, country)
                    )

                    break

                else:
                    dict_nets[bin_id].append((current_ip_index, LSB, country))

                    offset += LSB

        bin_contents = dict_nets[bin_id]
        bin_contents.sort()

        dict_nets[bin_id] = _merge_geo_ranges(bin_contents)

    nets = [(k, tuple(v)) for k,v in dict_nets.items()]
    nets.sort()

    dict_nets, geo_sigs = None, None

    return tuple(nets)

def _merge_geo_ranges(ls):
    temp_item, temp_list = [], []
    for t in ls:
        l = list(t)
        # if we have a temp item, it means we have an ongoing contigous range. if the first element in the current list
        # is equal to the last element in the temp list(+1), the networks are still contigous so we will merge them and
        # update the temp item.
        if (temp_item and l[0] == temp_item[1] + 1
                and l[2] == temp_item[2]):
            temp_item[1] = l[1]

        # applying current item to temp item since it didnt exist
        elif (not temp_item):
            temp_item = l

        # once a discontigious range is detected. the temp item for previous range will get appended to the list to be
        # returned as well as the current list.
        else:
            temp_list.append(tuple(temp_item))
            temp_item = l

    if ls and (not temp_list or temp_list[-1] not in [t, l]):
        temp_list.append(tuple(temp_item))

    return temp_list

def load_tlds():
    dns_proxy = load_configuration('dns_proxy')['dns_proxy']

    for tld, setting in dns_proxy['tlds'].items():
        yield (tld.strip('.'), setting)

# function to load in all keywords corresponding to enabled domain categories. the try/except
# is used to ensure bad keywords do not prevent the proxy from starting, though the bad keyword
# will be ommited from the proxy.
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
        return keywords
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

def calculate_file_hash(file_to_hash, *, path=f'{HOME_DIR}/', folder='data'):
    '''returns the sha256 secure hash of the file sent in'''
    with open(f'{path}{folder}/{file_to_hash}', 'rb') as f2h:
        file_hash = hashlib.sha256(f2h.read()).digest()

    return file_hash

def cfg_read_poller(watch_file, class_method=False):
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
                watcher = Watcher(watch_file, callback=function_to_wrap)
                watcher.watch(*args)

        else:
            @classmethod
            def wrapper(*args):
                watcher = Watcher(watch_file, callback=function_to_wrap)
                watcher.watch(*args)

        return wrapper
    return decorator

def cfg_write_poller(list_function):
    '''Automate class configuration file poll decorator. this decorator is only compatible with
    the dns proxy module whitelist/blacklist read/write operations'''

    def wrapper(*args):
        print(f'[+] Starting user defined {args[1]} timer')
        last_modified_time, new_args = 0, (*args, f'{args[1]}.json')
        # main loop calling the primary function for read/write change detection/polling
        # the recycle the saved hash file which is returned regardless of if it was changed or not
        while True:
            last_modified_time = list_function(*new_args, last_modified_time)

            time.sleep(FILE_POLL_TIMER)
    return wrapper


class ConfigurationManager:
    ''' Class to ensure process safe operations on configuration files. This class is written
    as a context manager and must be used as such. upon calling the context a file lock will
    be obtained or block until it can aquire the lock and return the class object to the caller.
    '''

    Log = None
    config_lock_file = f'{HOME_DIR}/dnx_system/config.lock'

    __slots__ = (
        '_config_lock', '_filename', '_data_written',
        '_std_path', '_system_path_file', '_usr_path_file',
        '_temp_file', '_temp_file_path'
    )

    @classmethod
    def set_log_reference(cls, ref):
        '''sets logging class reference for configuration manager specific errors.'''

        cls.Log = ref

    def __init__(self, config_file, file_path=None):
        self._data_written = False
        self._std_path = True
        if (file_path):
            self._std_path = False

        else:
            file_path = 'dnx_system/data'

        # backwards compatibility between specifying file ext and not.
        self._filename = config_file if config_file.endswith('.json') else f'{config_file}.json'

        self._system_path_file = f'{HOME_DIR}/{file_path}/{self._filename}'
        self._usr_path_file = f'{HOME_DIR}/dnx_system/data/usr/{self._filename}'

    # attempts to acquire lock on system config lock (blocks until acquired), then opens a temporary
    # file which the new configuration will be written to, and finally returns the class object.
    def __enter__(self):
        self._config_lock = open(self.config_lock_file, 'r+')

        # aquiring lock on shared lock file
        flock(self._config_lock, LOCK_EX)

        self._temp_file_path = f'{HOME_DIR}/dnx_system/data/usr/{token_urlsafe(10)}.json'
        self._temp_file = open(self._temp_file_path, 'w+')

        # changing file permissions and settings owner to dnx:dnx to not cause permissions issues
        # after copy.
        os.chmod(self._temp_file_path, 0o660)
        shutil.chown(self._temp_file_path, user=USER, group=GROUP)

        self.Log.debug(f'Config file lock aquired for {self._filename}.')

        return self

    # if there is no exception on leaving the context and data was written to the temp file the temporary
    # file will be renamed over the configuration file sent in by the caller. if an exception is raised
    # the temporary file will be deleted. The file lock will be released upon exiting
    def __exit__(self, exc_type, exc_val, traceback):
        replace_target = self._usr_path_file if self._std_path else self._system_path_file

        if (exc_type is None and self._data_written):
            os.replace(self._temp_file_path, replace_target)

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

            raise ValidationError('Unknown error. See log for details.')

    #will load json data from file, convert it to a python dict, then returned as object
    def load_configuration(self):
        ''' returns python dictionary of configuration file contents'''
        with open(self._system_path_file, 'r') as system_settings:
            system_settings = json.load(system_settings)

        if (self._std_path) and os.path.exists(self._usr_path_file):

            # loading user configurations (if exists)
            with open(self._usr_path_file, 'r') as usr_settings:
                usr_settings = json.load(usr_settings)

            # updating system settings dict with user settings to be used in memory/ by modules only.
            system_settings.update(usr_settings)

        return system_settings

    # accepts python dictionary to be serialized to json and written to file opened. will ensure
    # data gets fully rewrittin and if short than original the excess gets truncated.
    def write_configuration(self, data_to_write):
        '''writes configuration data as json to generated temporary file'''
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

    def __init__(self, watch_file, callback):
        self._watch_file = watch_file
        self._callback   = callback
        self._full_path  = f'{HOME_DIR}/dnx_system/data/usr/{watch_file}'

        self._last_modified_time = 0

    # will check file for change in set intervals, currently using global constant for config file polling
    def watch(self, *args):
        args = [*args, self._watch_file]

        # NOTE: initial load of data to accomodate the new usr dir. This may change in the future.
        # TODO: see if this can be wrapped into the while loop or if this is most efficient.
        self._callback(*args)

        while True:
            if (self.is_modified):
                self._callback(*args)

            else:
                time.sleep(FILE_POLL_TIMER)

    @property
    # if watch file has been modified will update modified time and return True, else return False
    def is_modified(self):
        if not os.path.isfile(self._full_path):
            return False

        modified_time = os.stat(self._full_path).st_mtime
        if (modified_time != self._last_modified_time):

            # updating shared modified time to reflect recent changes and return True notifying system of
            # a file change event
            self._last_modified_time = modified_time

            return True

        return False
