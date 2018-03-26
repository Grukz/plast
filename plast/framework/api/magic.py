# -*- coding: utf-8 -*-

from framework.contexts.logger import Logger as _log

import multiprocessing
import signal

class Hole:
    def __init__(self, target, action=None):
        self.target = target
        self.action = action

    def __enter__(self):
        pass

    def __exit__(self, exception, *args):
        if exception and issubclass(exception, self.target):
            if self.action:
                self.action()

            return True
        return False

class Pool:
    def __init__(self, processes=(multiprocessing.cpu_count() or 4)):
        self.processes = processes
        self.pool = multiprocessing.Pool(processes=self.processes, initializer=self.__worker_initializer)

        _log.debug("Initialized pool of <{}> concurrent process(es).".format(self.processes))

    def __enter__(self):
        return self.pool

    def __exit__(self, *args):
        with Hole(KeyboardInterrupt, action=self.__tear_down):
            self.pool.close()
            self.pool.join()

    def __tear_down(self):
        _log.warning("Waiting for concurrent process(es) to terminate before exiting.")

        self.pool.terminate()
        self.pool.join()

    def __worker_initializer(self):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
