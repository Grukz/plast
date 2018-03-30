# -*- coding: utf-8 -*-

from framework.api import magic as _magic
from framework.api.loader import Loader as _loader

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log
from framework.contexts.meta import Meta as _meta
from framework.contexts.types import Codes as _codes

from framework.core import reader as _reader
from framework.core import processor as _processor

import io
import multiprocessing
import os.path

try:
    import yara

except (
    ImportError,
    Exception):

    _log.fault("Import error.", trace=True)

class Engine:
    def __init__(self, case):
        self.case = case
        self.buffers = {}

    def __compile_ruleset(self, name, ruleset):
        try:
            buffer = io.BytesIO()
            yara.compile(ruleset, includes=True).save(file=buffer)
            self.buffers[ruleset] = buffer

            _log.debug("Precompilated ruleset <{}> in memory.".format(name))

        except (
            Exception,
            yara.Error):

            _log.exception("Failed to pre-compile ruleset <{}>.".format(ruleset))

    def __dispatch_jobs(self):
        with multiprocessing.Manager() as manager:
            queue = manager.Queue()

            reader = multiprocessing.Process(target=_reader.Reader(queue, {
                "target": self.case.resources["matches"],
                "format": self.case.arguments.format}).run)

            reader.daemon = True
            reader.start()

            _log.debug("Started reader subprocess to process queue result(s).")

            with _magic.Pool(processes=self.case.arguments.processes) as pool:
                for evidence in self.case.resources["evidences"]:
                    pool.starmap_async(
                        _processor.Processor(queue, self.case.arguments.hash_algorithms).run, 
                        [(evidence, self.buffers)], 
                        error_callback=_log.exception)

                    _log.debug("Mapped concurrent job to process evidence <{}>.".format(evidence))

            queue.put(_codes.DONE)

            with _magic.Hole(KeyboardInterrupt, action=lambda:_log.fault("Aborted due to manual user interruption <SIGINT>.")):
                reader.join()

    def __spawn_postprocessors(self):
        for postprocessor in self.case.arguments.post:
            Postprocessor = _loader.load_processor(postprocessor, _models.Post)(self.case)
            Postprocessor.__name__ = postprocessor

            _log.debug("Started <{}> session <{}>.".format(Postprocessor.__class__.__name__, Postprocessor.__name__))
            Postprocessor.run()
            _log.debug("Ended <{}> session <{}>.".format(Postprocessor.__class__.__name__, Postprocessor.__name__))

    def run(self):
        for name, ruleset in _loader.iterate_rulesets():
            self.__compile_ruleset(name, ruleset)

        self.__dispatch_jobs()
        self.__spawn_postprocessors()
