# -*- coding: utf-8 -*-

from framework.api.internal.renderer import Renderer as _renderer

from framework.contexts import errors as _errors
from framework.contexts.logger import Logger as _log
from framework.contexts.configuration import Configuration as _conf

import glob
import itertools
import multiprocessing
import os.path
import signal

__all__ = [
    "Hole",
    "Invocator",
    "Pool"
]

class Hole:
    """Swallows the given exception(s) by type."""

    def __init__(self, target, action=None):
        """
        .. py:function:: __init__(self, target, action=None)

        Initialization method for the class.

        :param self: current class instance
        :type self: class

        :param target: exception type to swallow, must inherit from the Python :code:`Exception` class
        :type target: class

        :param action: callback function to trigger when swallowing an exception
        :type action: class
        """

        self.target = target
        self.action = action

    def __enter__(self):
        """
        .. py:function:: __enter__(self)

        Callback method called when the context manager is invoked.

        :param self: current class instance
        :type self: class
        """

        pass

    def __exit__(self, exception, *args):
        """
        .. py:function:: __exit__(self, exception, *args)

        Exit method raised when leaving the context manager.

        :param self: current class instance
        :type self: class

        :param exception: exception raised
        :type exception: class

        :param *args: list of argument(s)
        :type *args: class

        :return: :code:`True` if an exception was swallowed, else :code:`False`
        :rtype: bool
        """

        if exception and issubclass(exception, self.target):
            if self.action:
                self.action()

            return True
        return False

class Invocator:
    """Wraps modules invocation by displaying debug messages."""

    def __init__(self, module):
        """
        .. py:function:: __init__(self, module)

        Initialization method for the class.

        :param self: current class instance
        :type self: class

        :param module: class inherited from the :code:`models` reference classes
        :type module: class
        """

        self.module = module

        _log.debug("Started <{}> session <{}>.".format(self.module.__class__.__name__, self.module.__name__))

    def __enter__(self):
        """
        .. py:function:: __enter__(self)

        Callback method called when the context manager is invoked.

        :param self: current class instance
        :type self: class
        """

        pass

    def __exit__(self, *args):
        """
        .. py:function:: __exit__(self, *args)

        Exit method raised when leaving the context manager.

        :param self: current class instance
        :type self: class

        :param *args: list of argument(s)
        :type *args: class
        """

        _log.debug("Ended <{}> session <{}>.".format(self.module.__class__.__name__, self.module.__name__))

class Pool:
    """Wrapper around :code:`multiprocessing.Pool` that automatically sets the :code:`SIGINT` signal handler and cleans up on error."""

    def __init__(self, processes=(multiprocessing.cpu_count() or _conf.FALLBACK_PROCESSES)):
        """
        .. py:function:: __init__(self, processes=(multiprocessing.cpu_count() or _conf.FALLBACK_PROCESSES))

        Initialization method for the class.

        :param self: current class instance
        :type self: class

        :param exception: number of concurrent process(es) to spawn
        :type exception: int
        """

        self.processes = processes
        self.pool = multiprocessing.Pool(processes=self.processes, initializer=self._worker_initializer)

        _log.debug("Initialized pool of <{}> concurrent process(es).".format(self.processes))

    def __enter__(self):
        """
        .. py:function:: __enter__(self)

        Callback method called when the context manager is invoked.

        :param self: current class instance
        :type self: class

        :return: instance of :code:`multiprocessing.Pool`
        :rtype: class
        """

        return self.pool

    def __exit__(self, *args):
        """
        .. py:function:: __exit__(self, *args)

        Exit method raised when leaving the context manager.

        :param self: current class instance
        :type self: class

        :param *args: list of argument(s)
        :type *args: class
        """

        with Hole(KeyboardInterrupt, action=self._tear_down):
            self.pool.close()
            self.pool.join()

    def _tear_down(self):
        """
        .. py:function:: _tear_down(self)

        Cleanup method called on error.

        :param self: current class instance
        :type self: class
        """

        _log.warning("Waiting for concurrent process(es) to terminate before exiting.")

        self.pool.terminate()
        self.pool.join()

    def _worker_initializer(self):
        """
        .. py:function:: _worker_initializer(self)

        Initializing method that sets the :code:`SIGINT` handler for every concurrent process spawned by :code:`multiprocessing.Pool`.

        :param self: current class instance
        :type self: class
        """

        signal.signal(signal.SIGINT, signal.SIG_IGN)
