#!/usr/bin/env python3

from __future__ import annotations

import threading

from copy import copy
from collections import deque
from struct import Struct
from functools import wraps

from dnx_gentools.def_typing import *
from dnx_gentools.def_constants import RUN_FOREVER, MSEC, fast_time, fast_sleep, str_join, space_join, comma_join

# ===============
# TYPING IMPORTS
# ===============
if (TYPE_CHECKING):
    from dnx_routines.logging import LogHandler_T

__all__ = (
    'looper', 'dynamic_looper',
    'ConfigurationMixinBase', 'Initialize',
    'dnx_queue', 'inspection_queue',
    'bytecontainer', 'structure',
    'classproperty',
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
            @wraps(loop_function)
            def wrapper(*args):

                # allowing kwargs in decorator setup to be passed into wrapped function allowing for local assignments
                # of variables to tighten the loop a bit.
                args = (*args, *[v for v in kwargs.values()])

                for _ in RUN_FOREVER:
                    loop_function(*args)

        else:
            @wraps(loop_function)
            def wrapper(*args):

                args = (*args, *[v for v in kwargs.values()])

                for _ in RUN_FOREVER:
                    loop_function(*args)

                    fast_sleep(sleep_len)

        return wrapper
    return decorator

def dynamic_looper(loop_function: Callable):
    '''loop decorator that will sleep for the returned integer amount.

    functions returning None will not sleep on the next iter and returning "break" will cancel the loop.
    '''
    @wraps(loop_function)
    def wrapper(*args):
        for _ in RUN_FOREVER:
            sleep_amount = loop_function(*args)
            if (sleep_amount == 'break'):
                break

            elif (not sleep_amount):
                continue

            fast_sleep(sleep_amount)

    return wrapper


class ConfigurationMixinBase:
    '''Base class for security module configuration Mixins.

    NOT defining slots to allow for primary parents to provide use/provide them.
    '''
    module_class: ModuleClasses

    def __init__(self):
        self._config_setup: bool = False

        self._initialize = Initialize()

        # calling the module's epoll handler __init__ method
        super().__init__()

    def configure(self, module_class: Optional[ModuleClasses] = None) -> None:
        '''blocking until settings are loaded/initialized.
        '''
        if (self._config_setup):
            raise RuntimeError('configuration setup should only be called once.')

        self._config_setup = True

        self.module_class = module_class

        # subclass hooke will provide log handler reference and threads to start
        log, thread_info, thread_count = self._configure()

        # ===============
        # INITIALIZATION
        # ===============
        self._initialize.set_logging(log, self.__class__.__name__)

        for target, args in thread_info:
            threading.Thread(target=target, args=args).start()

        # the length of returned tuple reflects the number of threads we need to wait on before returning.
        self._initialize.wait_for_threads(count=thread_count)

    def _configure(self) -> tuple[LogHandler_T, tuple, int]:
        '''module specific configuration initialization.
        '''
        raise NotImplementedError('module configuration method is not defined.')


class Initialize:
    '''class used to handle system module thread synchronization on process startup.

    ensures all threads have completed one loop before returning control to the caller.
    will block until the condition is met.

    note: LogHandler is optional so log messages will be bypassed if a handler is not provided (naturally).
    '''
    __slots__ = (
        '_log', '_name', '_initial_time',
        '_is_initializing', 'has_ran', '_timeout',
        '_thread_count', '_thread_ready',
    )

    def __init__(self, log: Optional[LogHandler_T] = None, name: str = '') -> None:
        self._log: LogHandler_T = log
        self._name: str = name

        self._initial_time: int = fast_time()

        self._is_initializing: bool = True
        self.has_ran: bool = False
        self._timeout: int = 0
        self._thread_count: int = 0
        self._thread_ready: set = set()

    def set_logging(self, log: LogHandler_T, name: str) -> None:
        '''alternate method to set logging references.
        '''
        self._log  = log
        self._name = name

    def wait_for_threads(self, *, count: int, timeout: int = 0) -> None:
        '''blocks until the checked in threads count has reached the wait for amount.
        '''
        if (not self._is_initializing or self.has_ran):
            raise RuntimeError('run has already been called for this instance.')

        self._thread_count = count
        self._timeout = timeout

        if (self._log):
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

        # overloading property reference to None to reduce code execution for subsequent thread loops.
        Initialize.done2 = None

        if (self._log):
            self._log.notice(f'{self._name} setup complete.')

    def done(self) -> None:
        '''inform the handler a thread has been initialized.

        using default thread name as dict key.
        '''
        # initialization is complete
        if (not self._is_initializing):
            return

        # this thread has already checked in.
        # this is a no op, but generates multiple debug messages, so filtering helps troubleshooting.
        thread_ident = threading.get_ident()
        if (thread_ident in self._thread_ready):
            return

        self._thread_ready.add(threading.get_ident())

        if (self._log):
            self._log.debug(f'{self._name} thread checkin.')

    @property
    def done2(self) -> bool:
        '''new form of dealing with thread initialization check-in.

        for short term compatibility, this will functionally wrap done(), providing identical functionality.

        because this is in property form, True will always be returned.
        once initialization is complete, the property reference will be overloaded with "None" to reduce code execution
        post initialization.
        '''
        self.done()

        return True

    def wait_in_line(self, *, wait_for: int) -> None:
        '''blocking call to wait for all lower number threads to complete before checking in and returning.

            initialize = Initialize(*args, **kwargs)
            initialize.wait_in_line(wait_for=2)

        this call has the potential to deadlock. positions must be sequential work as intended, but are not
        required to be called in order.
        '''
        if (not self._is_initializing):
            return

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

def dnx_queue(log: LogHandler_T, name: str = None) -> Callable[[...], Any]:
    '''decorator to add custom queue mechanism for any queue handling functions. This is a direct replacement of
    dynamic_looper for queues.

    example:
        @dnx_queue(Log, name='Server')
        def some_func(job):
            process(job)
    '''
    def decorator(func: Callable[[Any, ...], Any]):

        queue: deque = deque()
        queue_add: Callable[[Any], None] = queue.append
        queue_get: Callable[[], Any] = queue.popleft

        job_available: Event_T = threading.Event()
        job_wait: Callable[[Optional[float]], bool] = job_available.wait
        job_clear: Callable[[], None] = job_available.clear
        job_set: Callable[[], None] = job_available.set

        @wraps(func)
        def queue_handler(*args) -> NoReturn:
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

        def add(job: Any) -> None:
            '''adds a job to work queue, then flags event indicating a job is available.
            '''
            queue_add(job)
            job_set()

        queue_handler.__dict__['add'] = add
        return queue_handler

    return decorator

def request_queue():
    '''basic queueing mechanism for DNS requests received by the server.

    alternate [Event based] version to the "InspectionQueue" mechanism used by the security modules.
    optimized for single thread performance.
    '''
    request_queue = deque()
    request_queue_append = request_queue.append
    request_queue_get = request_queue.popleft

    request_ready = threading.Event()
    wait_for_request = request_ready.wait
    notify_ready = request_ready.set
    clear_ready = request_ready.clear

    class _RequestQueue:

        def return_ready(self) -> ListenerPackets:
            '''function generator returning requests from queue in FIFO order.

            calls will block if the queue is empty and will never time out.
            '''
            # blocking until at least one request has been received
            wait_for_request()

            # immediately clearing event, so we don't have to worry about it after loop. this prevents having to deal
            # with scenarios where a request was received in just after while loop, but just before reset. in this case
            # the request would be stuck until another was received.
            clear_ready()

            while request_queue:
                yield request_queue_get()

        # NOTE: first arg is because this gets referenced/called via an instance.
        def insert(self, client_query: ListenerPackets) -> None:

            request_queue_append(client_query)

            # notifying return_ready that there is a query ready to forward
            notify_ready()

    if (TYPE_CHECKING):
        return _RequestQueue

    return _RequestQueue()

def inspection_queue():
    '''thread safe (using semaphores) packet queue to allow for more efficient packet processing by
    the system modules.

    1 worker can be used for sequential processing of packets
            - see "RequestQueue" for an alternative to this
    >1 worker will allow packets to be processed concurrently
            - performance of threads will depend on ratio of holding gil to not holding gil
    '''

    queue = deque()
    queue_add = queue.append
    queue_get = queue.popleft

    sem = threading.Semaphore(0)
    notify_add = sem.release
    wait_for_job = sem.acquire

    class _InspectionQueue:

        def add(self, job: ProxyPackets) -> None:
            '''place packet into inspection queue for processing.
            '''
            queue_add(job)
            notify_add()

        def get(self) -> ProxyPackets:
            '''returns packet from inspection queue for processing.

            blocks until a packet is available.
            '''
            wait_for_job()
            job = queue_get()

            return job

    if (TYPE_CHECKING):
        return _InspectionQueue

    return _InspectionQueue()

def structure(obj_name: str, fields: Union[list, str]):
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
            super().__init__()

            self.buf: bytearray = _bytearray(size_of)

            for name in field_names:
                self[name] = 0

        def __repr__(self) -> str:
            return f'{self.__class__.__name__}({obj_name}, "{space_join(field_names)}")'

        def __str__(self) -> str:

            _fields = [f'{n}={v}({f})' for (n, v), f in _zip(self.items(), field_formats)]

            return f'{obj_name}({comma_join(_fields)})'

        def __call__(self, updates: tuple[tuple[str, int]] = None) -> _Structure:
            '''returns a copy of current field assignments.

            a dictionary can be used to insert updated values into the new container.

            a subsequent call to assemble is required to update the buffer if updates are provided on the call.
            '''
            new_container = _copy(self)

            # set args in the new instance if specified. this will overwrite any pre-set attributes.
            if (updates):
                for name, value in updates:

                    if (name not in field_names):
                        raise ValueError(f'attribute {name} does not exist in this container.')

                    new_container[name] = value

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
                super().__setattr__('buf', value)

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
            '''return packed attributes into a slotted buffer with creation order preserved.

            alternatively, buf can be accessed directly for quick changes.
            '''

            pack_fields(self.buf, 0, *self.values())

            return self.buf

    if (TYPE_CHECKING):
        return _Structure

    return _Structure()

def bytecontainer(obj_name: str, field_names: Union[list, str]):
    '''named tuple like class factory for storing raw byte sections with named fields.

    calling len on the container will return the sum of all bytes stored, not the number of fields.
    slots are being used to speed up attribute access.
    '''
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

    if (TYPE_CHECKING):
        return _ByteContainer

    return _ByteContainer()

class classproperty:
    '''class used as a decorator to allow class methods to be used as properties.
    '''
    def __init__(self, fget):
        self._fget = fget

    def __get__(self, owner_self, owner_class):
        return self._fget(owner_class)


# TYPE EXPORTS
if (TYPE_CHECKING):
    RequestQueue_T: TypeAlias = request_queue()
    InspectionQueue_T: TypeAlias = inspection_queue()
    Structure_T: TypeAlias       = structure('Structure', '')
    ByteContainer_T: TypeAlias   = bytecontainer('ByteContainer', '')

    __all__.extend(['RequestQueue_T', 'InspectionQueue_T', 'Structure_T', 'ByteContainer_T'])
