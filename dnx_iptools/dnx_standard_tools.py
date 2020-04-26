#!/usr/bin/env python3

import time
import struct
import threading

from copy import copy
from collections import deque

fast_time = time.time
fast_sleep = time.sleep

__all__ = (
    'looper', 'dynamic_looper',
    'Initialize', 'dnx_queue', 'DNXQueue',
    'ByteContainer', 'classproperty', 'keep_info'
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
        while not self._initial_load_complete:
            time.sleep(1)

        self.has_ran = True
        self._is_initializing = False
        self._thread_ready = None

        self._Log.notice(f'{self._name} setup complete.')

    def done(self):
        '''inform the handler a thread has been initialized. using default thread name as dict key.'''
        if (not self._is_initializing): return

        self._thread_ready.add(threading.get_ident())

        self._Log.debug(f'{self._name} thread checkin.')

    def wait_in_line(self, position):
        '''blocking call to wait for all lower number threads to complete before checking in and returning.

        this call has the potential to deadlock. positions must be sequential work as intended, but are not
        required to be called in order.

        '''
        if (not self._is_initializing): return

        while not position == len(self._thread_ready):
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
    '''decorator to add custom queue mechanism for any queue handling functions. This
    is a direct replacement for dynamic_looper for queues. if used on a class method
    set class_method argument to True.

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
            if (Log):
                Log.debug(f'{name}/dnx_queue started.')
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
                        fast_sleep(.001)

        def add(job):
            '''adds job to work queue, then marks event indicating a job is available.'''
            queue_add(job)
            job_set()

        wrapper.add = add
        return wrapper

    return decorator


class ByteContainer:
    '''named tuple like class for storing raw byte sections with named fields. calling
    len on the container will return sum of all bytes stored not amount of fields.'''
    def __init__(self, obj_name, field_names):
        self._obj_name = obj_name
        self._field_names = field_names.split()
        for name in self._field_names:
            setattr(self, name, '')

        self._byte_len = 0

    def __repr__(self):
        return f"{self.__class__.__name__}({self._obj_name}, '{' '.join(self._field_names)}')"

    def __str__(self):
        fields = [f'{n}={getattr(self, n)}' for n in self._field_names]

        return f"{self._obj_name}({', '.join(fields)})"

    def __call__(self, *args):
        if (len(args) != len(self._field_names)):
            raise TypeError(f'Expected {len(self._field_names)} arguments, got {len(args)}')

        new_container = copy(self)
        for name, value in zip(self._field_names, args):
            if (not isinstance(value, bytes)):
                raise TypeError('this container can only hold raw bytes.')
            new_container._byte_len += len(value)
            setattr(new_container, name, value)

        return new_container

    def __len__(self):
        return self._byte_len

    def __getitem__(self, position):
        return getattr(self, f'{self._field_names[position]}')

    def __iter__(self):
        yield from [getattr(self, x) for x in self._field_names]

    def update(self, field_name, new_value):
        if (field_name not in self._field_names):
            raise ValueError('field name does not exist.')

        if (not isinstance(new_value, bytes)):
            raise TypeError('this container can only hold raw bytes.')

        self._byte_len -= len(getattr(self, field_name))
        setattr(self, field_name, new_value)
        self._byte_len += len(new_value)


class classproperty:
    '''class used as a decorator to allow class methods to be used as properties.'''
    def __init__(self, fget):
        self._fget = fget

    def __get__(self, owner_self, owner_class):
        return self._fget(owner_class)

# FROM PYTHON.ORG DECORATOR LIBRARY # NOTE: does this work???
def keep_info(decorator):
    '''Simply apply @keep_info to your decorator and it will automatically preserve
    the docstring and function attributes of functions to which it is applied.'''
    def new_decorator(f):
        g = decorator(f)
        g.__name__ = f.__name__
        g.__doc__ = f.__doc__
        g.__dict__.update(f.__dict__)
        return g

    new_decorator.__name__ = decorator.__name__
    new_decorator.__doc__ = decorator.__doc__
    new_decorator.__dict__.update(decorator.__dict__)
    return new_decorator
