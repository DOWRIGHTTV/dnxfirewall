#!/usr/bin/env python3

from __future__ import annotations

from __future__ import annotations

import threading

from copy import copy
from collections import deque
from struct import Struct
from functools import wraps

from dnx_gentools.def_constants import RUN_FOREVER, MSEC, fast_time, fast_sleep, str_join, space_join, comma_join
from dnx_gentools.def_typing import *

__all__ = (
    'looper', 'dynamic_looper',
    'Initialize', 'dnx_queue',
    'bytecontainer', 'structure',
    'classproperty'
)

def looper(sleep_len: int, **kwargs):
    '''
    loop decorator calling sleeping for specified length. length is sent in on decorator argument. if no value
    is sent in the loop will continue immediately. kwargs can be sent in to provide locally assigned var access. the
    kwargs will be converted to args before passing to function.

        @looper(NO_DELAY, some_var=10)
        def func(some_var):
            do something
    '''
    if not isinstance(sleep_len, int):
        raise TypeError('sleep length must be an integer.')

    elif (sleep_len < 0):
        raise ValueError('sleep length must be >= 0.')

    def decorator(loop_function):

        # pre-wrap optimization to remove sleep_len condition after every iteration if not set.
        if (not sleep_len):
            def wrapper(*args):

                # allowing kwargs in decorator setup to be pass into wrapped function. this will allow for local
                # assignments of variables to tighten the loop a bit.
                args = (*args, *[v for v in kwargs.values()])

                for _ in RUN_FOREVER:
                    loop_function(*args)

        else:
            def wrapper(*args):

                args = (*args, *[v for v in kwargs.values()])

                for _ in RUN_FOREVER:
                    loop_function(*args)

                    fast_sleep(sleep_len)

        return wrapper
    return decorator

def dynamic_looper(loop_function: Callable):
    '''loop decorator that will sleep for the returned integer amount. functions returning None will
    not sleep on next iter and returning "break" will cancel the loop.'''
    def wrapper(*args):
        for _ in RUN_FOREVER:
            sleep_amount = loop_function(*args)
            if (sleep_amount == 'break'): break
            elif (not sleep_amount): continue

            fast_sleep(sleep_amount)

    return wrapper


class Initialize:
    '''class used to handle system module thread synchronization on process startup. this will ensure all
    threads have completed one loop before returning control to the caller. will block until condition is met.'''

    def __init__(self, log: Type[LogHandler], name: str):
        self._log  = log
        self._name = name

        self._initial_time = fast_time()

        self.has_ran: bool = False
        self._timeout: Optional[int] = None
        self._is_initializing: bool = True
        self._thread_count: int = 0
        self._thread_ready = set()

    def wait_for_threads(self, *, count: int, timeout: Optional[int] = None) -> None:
        '''blocks until the checked in threads count has reached the wait for amount.'''
        if (not self._is_initializing or self.has_ran):
            raise RuntimeError('run has already been called for this self.')

        self._thread_count = count
        self._timeout = timeout

        self._log.notice(f'{self._name} setup waiting for threads: {count}.')

        # blocking until all threads check in by individually calling done method
        while not self._initial_load_complete:

            if (self._timeout_reached):
                self._log.error(
                    f'{self._name} init timed out while waiting for '
                    f'{self._thread_count-len(self._thread_ready)}/{self._thread_count} threads'
                )

            fast_sleep(1)

        self.has_ran = True
        self._is_initializing = False

        self._log.notice(f'{self._name} setup complete.')

    def done(self) -> None:
        '''inform the handler a thread has been initialized. using default thread name as dict key.'''
        if (not self._is_initializing): return

        self._thread_ready.add(threading.get_ident())

        self._log.debug(f'{self._name} thread checkin.')

    def wait_in_line(self, *, wait_for: int) -> None:
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
    def _initial_load_complete(self) -> bool:
        if (self._thread_count == len(self._thread_ready)):
            return True

        return False

    @property
    def _timeout_reached(self) -> bool:
        if (not self._timeout):
            return False

        if (fast_time() > self._initial_time + self._timeout):
            return True

        return False

def dnx_queue(log: Type[LogHandler], name: str = None) -> Callable:
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

        def wrapper(*args):
            log.informational(f'{name}/dnx_queue started.')

            for _ in RUN_FOREVER:
                job_wait()
                # clearing job notification
                job_clear()
                # processing all available jobs
                while queue:
                    job = queue_get()
                    try:
                        func(*args, job)
                    except Exception as E:
                        log.warning(f'error while processing a {name}/dnx_queue started job. | {E}')

                        fast_sleep(MSEC)

        def add(job):
            '''adds job to work queue, then marks event indicating a job is available.'''

            queue_add(job)
            job_set()

        wrapper.add = add
        return wrapper

    return decorator

def structure(obj_name: str, fields: Union[List, str]) -> Structure:
    '''named tuple like class factory for storing int values of raw byte sections with named fields.

    calling len on the container will return sum of all bytes stored not amount of fields. slots are being used to
    speed up attribute access. attribute type is not checked and can be truncated if incorrectly specified.

    note: currently < 1 byte attributes are not supported. some form of eval partial will likely be implemented.
    '''

    if not isinstance(fields, list):
        fields = fields.split()

    # used to lock in size of structure and associate struct packing functions for each field
    _formats = {'B': 1, 'H': 2, 'L': 4}

    # parsing arguments, splitting format with field name and building list(converted to tuple after) for each, and
    # calculating the container size as it is in packed byte form.
    size_of, field_names, field_formats = 0, [], []
    for field in fields:
        try:
            field_format, field_name = field.split(',')
        except:
            raise SyntaxError('incorrect syntax of field. ex L,long_field')

        if (field_format not in _formats):
            raise ValueError(f'unsupported integer format. use {list(_formats)}')

        size_of += _formats[field_format]
        field_names.append(field_name)
        field_formats.append(field_format)

    # converting lists to tuple for smaller memory footprint and immutability
    field_names = tuple(field_names)
    field_formats = tuple(field_formats)

    format_str = '>' + str_join(field_formats)
    pack_fields = Struct(format_str).pack_into

    # defining globals/builtins as closure for lookup performance (almost 2x faster)
    _copy = copy
    _zip = zip
    _sum = sum
    _setattr = setattr
    _getattr = getattr
    _bytearray = bytearray

    class _Structure(dict):

        __slots__ = ('buf',)

        def __init__(self):

            self.buf: bytearray = _bytearray(size_of)

            for name in field_names:
                self[name] = 0

        def __repr__(self) -> str:
            return f'{self.__class__.__name__}({obj_name}, "{space_join(field_names)}")'

        def __str__(self) -> str:

            _fields = [f'{n}={v}({f})' for (n, v), f in _zip(self.items(), field_formats)]

            return f'{obj_name}({comma_join(_fields)})'

        def __call__(self, **kwargs) -> Structure:
            '''returns a copy of current field assignments.

            kwargs can be used to insert updated values which will be copied over to new containers of the same type. a
            good use case for this is to fill out fields that are constants and can be streamlined to simplify
            external byte string creation logic. This is an alternative method to assignment at container creation.
            '''

            new_container = _copy(self)

            # set args in new instance if specified. this will overwrite any pre-set attributes. kwargs can be used to
            # pre define values at creation of new container.
            if (kwargs):
                for name, value in kwargs.items():

                    if (name not in field_names):
                        raise ValueError(f'attribute {name} does not exist in this container.')

                    new_container[name] = value

                # pre packing the buffer with updated field values
                new_container.assemble()

            return new_container

        def __len__(self) -> int:

            return size_of

        def __add__(self, other: bytearray) -> bytearray:

            return self.buf + other

        def __radd__(self, other: bytearray) -> bytearray:

            return other + self.buf

        def __iter__(self):

            yield from self.values()

        def __setattr__(self, key: str, value: int) -> None:

            if (key == 'buf'):
                super().__setattr__('buf', _bytearray(size_of))

            elif (key not in self):
                raise AttributeError(f'attribute {key} does not exist in this container.')

            else:
                self[key] = value

        def __getattr__(self, key: str) -> int:

            try:
                return self.buf if key == 'buf' else self[key]
            except KeyError:
                raise AttributeError(f'attribute {key} does not exist in this container.')

        def assemble(self) -> bytearray:
            '''pack attributes into slotted buf with creation order preserved then returns buf reference.

            alternatively, buf can be accessed directly for quick changes.
            '''

            pack_fields(self.buf, 0, *self.values())

            return self.buf

    return _Structure()

def bytecontainer(obj_name: str, field_names: Union[List, str]) -> ByteContainer:
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
    _bytearray = bytearray

    class _ByteContainer:

        __slots__ = (*field_names,)

        def __init__(self):
            for name in field_names:
                _setattr(self, name, b'')

        def __repr__(self):
            return f"{self.__class__.__name__}({obj_name}, '{' '.join(field_names)}')"

        def __str__(self):
            fields = [f'{fn}={_getattr(self, fn)}' for fn in field_names]

            return f"{obj_name}({', '.join(fields)})"

        def __call__(self, *args):
            if (_len(args) != len_fields):
                raise TypeError(f'Expected {len_fields} arguments, got {_len(args)}')

            new_container = _copy(self)
            for name, value in _zip(field_names, args):
                _setattr(new_container, name, value)

            return new_container

        def __len__(self):
            return _sum([_len(_getattr(self, field_name)) for field_name in field_names])

        def __getitem__(self, position):
            return _getattr(self, f'{field_names[position]}')

        def __iter__(self):
            yield from [_getattr(self, fn) for fn in field_names]

        def __add__(self, other):
            ba = _bytearray()
            for name in field_names:
                ba += _getattr(self, name)

            return ba + other

        def __radd__(self, other):
            ba = _bytearray()
            for name in field_names:
                ba += _getattr(self, name)

            return other + ba

    return _ByteContainer()

class classproperty:
    '''class used as a decorator to allow class methods to be used as properties.'''
    def __init__(self, fget):
        self._fget = fget

    def __get__(self, owner_self, owner_class):
        return self._fget(owner_class)
