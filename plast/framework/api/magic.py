# -*- coding: utf-8 -*-

from framework.api.renderer import Renderer as _render

from framework.contexts import errors as _errors
from framework.contexts.logger import Logger as _log

import multiprocessing
import os.path
import signal

class Hole:
    """Swallows the given exception(s) by type."""

    def __init__(self, target, action=None):
        """
        Initialization method for the class.

        Parameter(s)
        ------------
        self [namespace] current class instance
        target [namespace] exception type to swallow, must inherit from the default `Exception` class
        action [namespace] callback to call when swallowing an exception
        """

        self.target = target
        self.action = action

    def __enter__(self):
        """
        Callback method called when the context manager is invoked.

        Parameter(s)
        ------------
        self [namespace] current class instance
        """

        pass

    def __exit__(self, exception, *args):
        """
        Exit method raised when leaving the context manager.

        Parameter(s)
        ------------
        self [namespace] current class instance
        exception [namespace] exception raised
        *args [list] list of argument(s)

        Return value(s)
        ---------------
        [bool] `True` if an exception was swallowed, else `False`
        """

        if exception and issubclass(exception, self.target):
            if self.action:
                self.action()

            return True
        return False

class Pool:
    """Wrapper around `multiprocessing.Pool` that automatically sets the `SIGINT` signal handler and cleans up on error."""

    def __init__(self, processes=(multiprocessing.cpu_count() or 4)):
        """
        Initialization method for the class.

        Parameter(s)
        ------------
        self [namespace] current class instance
        processes [int] number of concurrent process(es) to spawn
        """

        self.processes = processes
        self.pool = multiprocessing.Pool(processes=self.processes, initializer=self.__worker_initializer)

        _log.debug("Initialized pool of <{}> concurrent process(es).".format(self.processes))

    def __enter__(self):
        """
        Callback method called when the context manager is invoked.

        Parameter(s)
        ------------
        self [namespace] current class instance

        Return value(s)
        ---------------
        [namespace] instance of `multiprocessing.Pool`
        """

        return self.pool

    def __exit__(self, *args):
        """
        Exit method raised when leaving the context manager.

        Parameter(s)
        ------------
        self [namespace] current class instance
        *args [list] list of argument(s)
        """

        with Hole(KeyboardInterrupt, action=self._tear_down):
            self.pool.close()
            self.pool.join()

    def _tear_down(self):
        """
        Cleanup method called on error.

        Parameter(s)
        ------------
        self [namespace] current class instance
        """

        _log.warning("Waiting for concurrent process(es) to terminate before exiting.")

        self.pool.terminate()
        self.pool.join()

    def __worker_initializer(self):
        """
        Initializing method that sets the `SIGINT` handler for every concurrent process spawned by `multiprocessing.Pool`.

        Parameter(s)
        ------------
        self [namespace] current class instance
        """

        signal.signal(signal.SIGINT, signal.SIG_IGN)

class Invocator:
    """Wraps modules invocation by displaying debug messages."""

    def __init__(self, module):
        """
        Initialization method for the class.

        Parameter(s)
        ------------
        self [namespace] current class instance
        module [namespace] class inherited from the `models` reference classes
        """

        self.module = module

        _log.debug("Started <{}> session <{}>.".format(self.module.__class__.__name__, self.module.__name__))

    def __enter__(self):
        """
        Callback method called when the context manager is invoked.

        Parameter(s)
        ------------
        self [namespace] current class instance
        """

        pass

    def __exit__(self, *args):
        """
        Exit method raised when leaving the context manager.

        Parameter(s)
        ------------
        self [namespace] current class instance
        *args [list] list of argument(s)
        """


        _log.debug("Ended <{}> session <{}>.".format(self.module.__class__.__name__, self.module.__name__))

def _iterate_files(iterator):
    """
    Iterates over file(s) and yields the corresponding path if existing.

    Parameter(s)
    ------------
    iterator [list] list of file(s) path(s)

    Return value(s)
    ---------------
    [str] path to the existing file(s)
    """

    for item in iterator:
        if not os.path.isfile(item):
            _log.error("File not found <{}>.".format(item))
            continue

        yield item

def _iterate_matches(target):
    """
    Iterates over match(es) and yields a Python dictionary representation of each.

    Parameter(s)
    ------------
    target [str] path to the file containing the match(es)

    Return value(s)
    ---------------
    [dict] Python dictionary representation of the match
    """

    with open(target) as matches:
        for match in matches:
            try:
                yield _render.from_json(match)

            except (
                _errors.EncodingError,
                _errors.InvalidObject):

                _log.error("Failed to interpret match <{}>.".format(match))
