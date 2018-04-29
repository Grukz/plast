# -*- coding: utf-8 -*-

from framework.api import magic as _magic
from framework.api.loader import Loader as _loader

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log
from framework.contexts.types import Codes as _codes

from framework.core import reader as _reader
from framework.core import processors as _processors

import ctypes
import io
import multiprocessing

try:
    import yara

except (
    ImportError,
    Exception):

    _log.fault("Import error.", trace=True)

class Engine:
    """Dispatches the processing to asynchronous jobs."""

    def __init__(self, case):
        """
        .. py:function:: __init__(self, case)

        Initialization method for the class.

        :param self: current class instance
        :type self: class

        :param case: filled :code:`contexts.Case` instance
        :type case: class
        """

        self.case = case
        self.buffers = {}

    def _compile_ruleset(self, name, ruleset):
        """
        .. py:function:: _compile_ruleset(self, name, ruleset)

        Compiles and saves YARA rule(s) to the dictionary to be passed to the asynchronous job(s).

        :param self: current class instance
        :type self: class

        :param name: name of the ruleset file to compile the rule(s) from
        :type name: str

        :param ruleset: absolute path to the ruleset file to compile the rule(s) from
        :type ruleset: str
        """

        try:
            buffer = io.BytesIO()

            rules = yara.compile(ruleset, includes=True)
            rules.save(file=buffer)

            self.buffers[ruleset] = buffer

            _log.debug("Precompilated YARA ruleset <{}> in memory with a total of <{}> valid rule(s).".format(name, sum(1 for _ in rules)))
            return True

        except (
            Exception,
            yara.Error):

            _log.exception("Failed to pre-compile ruleset <{}>.".format(ruleset))

        return False

    def _dispatch_jobs(self):
        """
        .. py:function:: _dispatch_jobs(self)

        Dispatches the processing task(s) to the subprocess(es).

        :param self: current class instance
        :type self: class

        :return: number of match(es)
        :rtype: int
        """

        with multiprocessing.Manager() as manager:
            queue = manager.Queue()
            results = (multiprocessing.Lock(), multiprocessing.Value(ctypes.c_int, 0))

            reader = multiprocessing.Process(target=_reader.Reader(queue, results, {
                "target": self.case.resources["matches"],
                "format": self.case.arguments.format}).run)

            reader.daemon = True
            reader.start()

            _log.debug("Started reader subprocess to process queue result(s).")

            with _magic.Pool(processes=self.case.arguments.processes) as pool:
                for file in self.case.resources["evidences"]["files"]:
                    pool.starmap_async(
                        _processors.File(self.case.arguments.hash_algorithms, self.case.arguments.callbacks, queue).run, 
                        [(file, self.buffers)], 
                        error_callback=_log.inner_exception)

                    _log.debug("Mapped concurrent job to process evidence <{}>.".format(file))

                for process in self.case.resources["evidences"]["processes"]:
                    pool.starmap_async(
                        _processors.Process(self.case.arguments.callbacks, queue).run, 
                        [(process, self.buffers)], 
                        error_callback=_log.inner_exception)

                    _log.debug("Mapped concurrent job to process live process matching PID <{}>.".format(process))

            queue.put(_codes.DONE)

            with _magic.Hole(KeyboardInterrupt, action=lambda:_log.fault("Aborted due to manual user interruption <SIGINT>.")):
                reader.join()

            return results[1].value

    def _invoke_postprocessors(self):
        """
        .. py:function:: _invoke_postprocessors(self)

        Invoke the selected :code:`models.Post` module(s).

        :param self: current class instance
        :type self: class
        """

        for postprocessor in self.case.arguments.post:
            Postprocessor = _loader.load_processor(postprocessor, _models.Post)()
            Postprocessor.__name__ = postprocessor

            with _magic.Invocator(Postprocessor):
                Postprocessor.run(self.case)

    def run(self):
        """
        .. py:function:: run(self)

        Main entry point for the class.

        :param self: current class instance
        :type self: class
        """

        count = 0

        for name, ruleset in _loader.iterate_rulesets():
            if self._compile_ruleset(name, ruleset):
                count += 1

        _log.info("Applying a total of <{}> YARA ruleset(s).".format(count))
        del count

        if not self._dispatch_jobs():
            _log.warning("Skipping <{}> module(s) invocation.".format(_models.Post.__name__))
            return

        self._invoke_postprocessors()
