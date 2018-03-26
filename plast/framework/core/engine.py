# -*- coding: utf-8 -*-

from framework.api.loader import Loader as _loader

from framework.contexts.logger import Logger as _log
from framework.contexts.meta import Meta as _meta
from framework.contexts.types import Codes as _codes

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

    def __compile_ruleset(self, ruleset):
        try:
            buffer = io.BytesIO()
            yara.compile(ruleset, includes=True).save(file=buffer)

            self.buffers[ruleset] = buffer

        except (
            Exception,
            yara.Error):

            _log.exception("Failed to pre-compile ruleset <{}>.".format(ruleset))

    # def __dispatch_jobs(self, file="matches.json"):
    #     with multiprocessing.Manager() as manager:
    #         queue = manager.Queue()

    #         self.output_file = os.path.join(self.case.resources["case"], file)

    #         reader = multiprocessing.Process(target=_reader.Reader(queue, self.output_file, self.case.arguments.format).run)
    #         reader.daemon = True
    #         reader.start()

    #         _log.debug("Started reader subprocess to process queue result(s).")

    #         with _magic.Pool(processes=self.case.arguments.processes) as pool:
    #             _log.debug("Initialized pool of <{}> concurrent process(es) to process evidence(s).".format(self.case.arguments.processes))

    #             for ruleset, yara_buffer in self.buffers.items():
    #                 for evidence in self.case.resources["evidences"]:
    #                     _log.debug("Mapping concurrent process to process evidence <{}> with ruleset <{}>.".format(evidence, ruleset))
    #                     pool.map_async(
    #                         _processor.Processor(queue, evidence, self.buffers).run, 
    #                         [], 
    #                         error_callback=_log.exception)

    #         queue.put(_codes.DONE)

    #         try:
    #             reader.join()

    #         except KeyboardInterrupt:
    #             _log.warning("Waiting for concurrent process(es) to terminate before exiting.")
    #             _log.fault("Aborted due to manual user interruption <SIGINT>.")

    def run(self):
        for name, ruleset in _loader.iterate_rulesets():
            _log.debug("Pre-compilating ruleset <{}> in memory.".format(name))
            self.__compile_ruleset(ruleset)

        # self.__dispatch_jobs()
