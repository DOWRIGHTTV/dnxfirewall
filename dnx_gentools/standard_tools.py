#!/usr/bin/env python3

import time
import struct
import threading

from copy import copy
from collections import deque

from dnx_sysmods.configure.def_constants import MSEC, fast_time, fast_sleep

__all__ = (
    'looper', 'dynamic_looper',
    'Initialize', 'dnx_queue', 'DNXQueue',
    'bytecontainer', 'classproperty', 'keep_info'
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
    # TODO: this is broken. it doesnt track based on iniactivity either???
    def _timeout_reached(self):
        if (not self._timeout):
            return False

        if (fast_time() > self._initial_time + self._timeout):
            return True

        return False

def dnx_queue(Log, name=None):
    '''decorator to add custom queue mechanism for any queue handling functions. This
    is a direct replacement for dynamic_looper for queues.


    WTF IS THIS -> if used on a class method set class_method argument to True.

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
        # methods inherently. if that is the case does @classmethod decorator need to be on initial method?
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
                        # TODO: see if we should just send in the queue reference and perform the pop in the called func. if
                        # we do this we would probably want it to be optional and use a conditional set on start to identify.
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


class DNXQueue:
    '''small class to provide a custom queue mechanism for any queue handling functions. This
    is a direct replacement for dynamic_looper for queues. this is to be used as a decorator,
    but it requires an active instance prior to decoration.

    example:
        dnx_queue = DNXQueue(Log)

        @dnx_queue
        def some_func(job):
            process(job)

    '''
    __slots__ = (
        '_Log', '_queue', '_func', '_job_available', '_name'
    )

    def __init__(self, Log, name=None):
        self._Log   = Log
        self._name  = name
        self._queue = deque()

        self._job_available = threading.Event()

    def __call__(self, func):
        self._func = func

        return self._looper

    def _looper(self, instance):
        '''waiting for job to become available. once available the, event will be reset
        and the decorated function will be called with the return of queue pop as an
        argument. runs forever.'''
        self._Log.debug(f'{self._name}/{self.__class__.__name__} started.')
        while True:
            self._job_available.wait()
            # processing all available jobs
            self._job_available.clear()
            while self._queue:
                try:
                    job = self._queue.popleft()
                    self._func(instance, job)
                except Exception as E:
                    self._Log.warning(f'error while processing a {self._name}/{self.__class__.__name__} job. | {E}')
                    fast_sleep(.001)

    def add(self, job):
        '''adds job to work queue, then marks event indicating a job is available.'''
        self._queue.append(job)
        self._job_available.set()


def bytecontainer(obj_name, field_names):
    '''named tuple like class factory for storing raw byte sections with named fields. calling
    len on the container will return sum of all bytes stored not amount of fields. slots are
    being used to speed up attribute access.'''

    if not isinstance(field_names, list):
        field_names = field_names.split()

    class ByteContainer:

        __slots__ = (
            '_obj_name', '_field_names', '_len_fields',
            *field_names
        )

        def __init__(self, obj_name, field_names):
            self._obj_name = obj_name
            self._field_names = field_names
            for name in field_names:
                setattr(self, name, '')

            self._len_fields = len(field_names)

        def __repr__(self):
            return f"{self.__class__.__name__}({self._obj_name}, '{' '.join(self._field_names)}')"

        def __str__(self):
            fast_get = self.__getattribute__
            fields = [f'{n}={fast_get(n)}' for n in self._field_names]

            return f"{self._obj_name}({', '.join(fields)})"

        def __call__(self, *args):
            if (len(args) != self._len_fields):
                raise TypeError(f'Expected {self._len_fields} arguments, got {len(args)}')

            new_container = copy(self)
            for name, value in zip(self._field_names, args):
                setattr(new_container, name, value)

            return new_container

        def __len__(self):
            fast_get = self.__getattribute__

            return sum([len(fast_get(field_name)) for field_name in self._field_names])

        def __getitem__(self, position):
            return getattr(self, f'{self._field_names[position]}')

        def __iter__(self):
            fast_get = self.__getattribute__

            yield from [fast_get(x) for x in self._field_names]

        # NOTE: consider removing this for direct access. this used to provide some input validation, but now that
        # it has been removed, the method call itself is pretty worthless.
        def update(self, field_name, new_value):
           setattr(self, field_name, new_value)

    return ByteContainer(obj_name, field_names)


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
