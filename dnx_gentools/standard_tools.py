#!/usr/bin/env python3

import threading

from copy import copy
from collections import deque

from dnx_iptools.def_structs import byte_pack, short_pack, long_pack
from dnx_gentools.def_constants import MSEC, fast_time, fast_sleep, byte_join

__all__ = (
    'looper', 'dynamic_looper',
    'Initialize', 'dnx_queue',
    'bytecontainer', 'structure',
    'classproperty'
)

def looper(sleep_len):
    '''loop decorator calling sleeping for specified length. length is sent in on decorator argument. if no value
    is sent in the loop will continue immediately.'''
    if not isinstance(sleep_len, int):
        raise TypeError('sleep length must be an integer.')

    elif (sleep_len < 0):
        raise ValueError('sleep length must be >= 0.')

    def decorator(loop_function):
        def wrapper(*args):
            while True:
                loop_function(*args)

                if (sleep_len):
                    fast_sleep(sleep_len)

        return wrapper
    return decorator

def dynamic_looper(loop_function):
    '''loop decorator that will sleep for the returned integer amount. functions returning None will
    not sleep on next iter and returning "break" will cancel the loop.'''
    def wrapper(*args):
        while True:
            sleep_amount = loop_function(*args)
            if (sleep_amount == 'break'): break
            elif (not sleep_amount): continue

            fast_sleep(sleep_amount)

    return wrapper


class Initialize:
    '''class used to handle system module thread synchronization on process startup. this will ensure all
    threads have completed one loop before returning control to the caller. will block until condition is met.'''
    def __init__(self, Log, name):
        self._Log  = Log
        self._name = name

        self._initial_time = fast_time()

        self.has_ran = False
        self._timeout = None
        self._is_initializing = True
        self._thread_count = 0
        self._thread_ready = set()

    def wait_for_threads(self, *, count, timeout=None):
        '''will block until the checked in thread count has reach the sent in count.'''
        if (not self._is_initializing or self.has_ran):
            raise RuntimeError('run has already been called for this self.')

        self._thread_count = count
        self._timeout = timeout

        self._Log.notice(f'{self._name} setup waiting for threads: {count}.')

        # blocking until all threads check in by individually calling done method
        while not self._initial_load_complete and not self._timeout_reached:
            fast_sleep(1)

        self.has_ran = True
        self._is_initializing = False

        self._Log.notice(f'{self._name} setup complete.')

    def done(self):
        '''inform the handler a thread has been initialized. using default thread name as dict key.'''
        if (not self._is_initializing): return

        self._thread_ready.add(threading.get_ident())

        self._Log.debug(f'{self._name} thread checkin.')

    def wait_in_line(self, *, wait_for):
        '''blocking call to wait for all lower number threads to complete before checking in and returning.

            initialize = Initialize(*args, **kwargs)
            initialize.wait_in_line(wait_for=2)

        this call has the potential to deadlock. positions must be sequential work as intended, but are not
        required to be called in order.

        '''
        if (not self._is_initializing): return

        while wait_for < len(self._thread_ready):
            fast_sleep(1)

    @property
    def _initial_load_complete(self):
        if (self._thread_count == len(self._thread_ready)):
            return True

        return False

    @property
    def _timeout_reached(self):
        if (not self._timeout):
            return False

        if (fast_time() > self._initial_time + self._timeout):
            return True

        return False

def dnx_queue(Log, name=None):
    '''decorator to add custom queue mechanism for any queue handling functions. This is a direct replacement of
    dynamic_looper for queues.

    example:
        @dnx_queue(Log, name='Server')
        def some_func(job):
            process(job)

    '''
    def decorator(func):

        queue = deque()
        queue_add = queue.append
        queue_get = queue.popleft

        job_available = threading.Event()
        job_wait = job_available.wait
        job_clear = job_available.clear
        job_set = job_available.set

        # TODO: is this code compatible with class methods? the *args should make this compatible with class
        #  methods inherently. if that is the case does @classmethod decorator need to be on initial method?
        def wrapper(*args):
            if (Log):
                Log.informational(f'{name}/dnx_queue started.')

            while True:
                job_wait()
                # clearing job notification
                job_clear()
                # processing all available jobs
                while queue:
                    job = queue_get()
                    try:
                        func(*args, job)
                    except Exception as E:
                        if (Log):
                            Log.warning(f'error while processing a {name}/dnx_queue started job. | {E}')

                        fast_sleep(MSEC)

        def add(job):
            '''adds job to work queue, then marks event indicating a job is available.'''

            queue_add(job)
            job_set()

        wrapper.add = add
        return wrapper

    return decorator


def structure(obj_name, fields):
    '''named tuple like class factory for storing int values of raw byte sections with named fields. calling
    len on the container will return sum of all bytes stored not amount of fields. slots are being used to speed up
    attribute access. attribute type is not checked and can be truncated if incorrectly specified.

    note: currently < 1 byte attributes are not supported. some for of eval partial will likely be implemented in the
    near future.'''

    if not isinstance(fields, list):
        fields = fields.split()

    # used to lock in size of structure and associate struct packing functions for each field
    _pack_refs = {
        'B': (1, byte_pack),
        'H': (2, short_pack),
        'L': (4, long_pack),
    }

    # parsing arguments, splitting format with field name and building list(converted to tuple after) for each, and
    # calculating the container size as it is in packed byte form.
    size_of, field_packs, field_names, field_formats = 0, [], [], []
    for field in fields:
        try:
            field_format, field_name = field.split(',')
        except:
            raise SyntaxError('incorrect syntax of field. ex L,long_field')

        if field_format not in _pack_refs:
            raise ValueError(f'unsupported integer format. use {list(_pack_refs)}')

        _field_size, _pack_ref = _pack_refs.get(field_format)

        size_of += _field_size
        field_packs.append(_pack_ref)
        field_names.append(field_name)
        field_formats.append(field_format)

    # converting lists to tuple for smaller memory footprint and immutability
    field_packs = tuple(field_packs)
    field_names = tuple(field_names)
    field_formats = tuple(field_formats)

    # defining globals/builtins as closure for lookup performance (almost 2x faster)
    _copy = copy
    _zip = zip
    _sum = sum
    _setattr = setattr
    _getattr = getattr

    class Structure:

        __slots__ = (*field_names,)

        def __init__(self):

            for name in field_names:
                _setattr(self, name, 0)

        def __repr__(self):
            return f"{self.__class__.__name__}({obj_name}, '{' '.join(field_names)}')"

        def __str__(self):
            fast_get = self.__getattribute__

            _fields = [f'{n}={fast_get(n)}({f})' for n, f in _zip(field_names, field_formats)]

            return f"{obj_name}({', '.join(_fields)})"

        def __call__(self, **kwargs):
            new_container = _copy(self)

            # set args in new instance if specified. this will overwrite any pre set attributes. kwargs can be used to
            # pre define values at creation of new container.
            if (kwargs):
                for name, value in kwargs.items():

                    if (name not in field_names):
                        raise ValueError(f'attribute {name} does not exist in this container.')

                    _setattr(new_container, name, value)

            return new_container

        def __len__(self):

            return size_of

        def __getitem__(self, position):

            return _getattr(self, f'{field_names[position]}')

        def __iter__(self):
            fast_get = self.__getattribute__

            yield from [fast_get(x) for x in field_names]

        def pre_set_attributes(self, **kwargs):
            '''specify attributes to set as pre processor function. these values will get copied over to new containers
            of the same type. a good use case for this is to fill out fields that are constants and can be streamlined
            to simplify external byte string creation logic. This is an alternative method to assignment at container
            creation.'''

            for name, value in kwargs.items():

                # if key doesnt exist, will raise error. this method is a pre process so this will allow for quicker
                # debugging of code vs finding out some point in runtime there is an invalid attr.
                if (name not in field_names):
                    raise ValueError(f'attribute {name} does not exist in this container.')

                _setattr(self, name, value)

        def assemble(self):
            '''returns merged attributes in specified order as a single byte array. this is not stored and is
             recalculated on every call.'''

            fast_get = self.__getattribute__

            return byte_join([pack(fast_get(name)) for pack, name in _zip(field_packs, field_names)])

    struct = Structure()

    return struct

def bytecontainer(obj_name, field_names):
    '''named tuple like class factory for storing raw byte sections with named fields. calling
    len on the container will return sum of all bytes stored not amount of fields. slots are
    being used to speed up attribute access.'''

    if not isinstance(field_names, list):
        field_names = field_names.split()

    len_fields = len(field_names)

    _copy = copy
    _len = len
    _zip = zip
    _sum = sum
    _setattr = setattr
    _getattr = getattr

    class ByteContainer:

        __slots__ = (*field_names,)

        def __init__(self):
            for name in field_names:
                fast_set(name, b'')

        def __repr__(self):
            return f"{self.__class__.__name__}({obj_name}, '{' '.join(field_names)}')"

        def __str__(self):
            fields = [f'{fn}={fast_get(fn)}' for fn in field_names]

            return f"{obj_name}({', '.join(fields)})"

        def __call__(self, *args):
            if (_len(args) != len_fields):
                raise TypeError(f'Expected {len_fields} arguments, got {_len(args)}')

            new_container = _copy(self)
            for name, value in _zip(field_names, args):
                _setattr(new_container, name, value)

            return new_container

        def __len__(self):
            return _sum([_len(fast_get(field_name)) for field_name in field_names])

        def __getitem__(self, position):
            return fast_get(f'{field_names[position]}')

        def __iter__(self):
            yield from [fast_get(fn) for fn in field_names]

    container = ByteContainer()
    fast_get = container.__getattribute__
    fast_set = container.__setattr__

    return ByteContainer()

class classproperty:
    '''class used as a decorator to allow class methods to be used as properties.'''
    def __init__(self, fget):
        self._fget = fget

    def __get__(self, owner_self, owner_class):
        return self._fget(owner_class)
