# -*- coding: utf-8 -*-

from framework.api.loader import Loader as _loader

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

import framework.processors.callback as _callback

import datetime
import hashlib
import os.path

try:
    import yara

except (
    ImportError,
    Exception):

    _log.fault("Import error.", trace=True)

class Processor:
    """Core multiprocessed class that processes the evidence(s) asynchronously."""

    def __init__(self, algorithms, callbacks, queue):
        """
        Initialization method that sets the different command-line argument(s).

        Parameter(s)
        ------------
        self [namespace] current class instance
        algorithms [list] list containing the name of the hash algorithm(s) to use
        callbacks [list] list containing the name of the models.Callback modules to invoke
        queue [namespace] multiprocessing.Queue instance
        """

        self.algorithms = algorithms
        self.queue = queue
        self.callbacks = callbacks

    def _parse_memory_buffers(self):
        """
        Parses memory buffers to retrieve the content of the YARA rules to apply.

        Parameter(s)
        ------------
        self [namespace] current class instance
        """

        for ruleset, buffer in self.buffers.items():
            buffer.seek(0)
            self.buffers[ruleset] = yara.load(file=buffer)

    def _compute_hash(self, evidence, algorithm="sha256", buffer_size=65536):
        """
        Computes the hash from the evidence's data.

        Parameter(s)
        ------------
        self [namespace] current class instance
        evidence [str] absolute path to the evidence to compute the hash from
        algorithm [str] name of the hash algorithm to compute (defaults to SHA256)
        buffer_size [int] size of the buffer

        Return value(s)
        ---------------
        [str] hexadecimal digest of the given file
        """

        with open(evidence, "rb") as file:
            cipher = getattr(hashlib, algorithm)()

            while True:
                data = file.read(buffer_size)

                if not data:
                    break

                cipher.update(data)
                
        return cipher.hexdigest()

    def _invoke_callbacks(self, data):
        """
        Invokes the selected models.Callback module(s) with the matching data.

        Parameter(s)
        ------------
        self [namespace] current class instance
        data [dict] dictionary containing the match data
        """

        for name in self.callbacks:
            _loader.load_processor(name, _models.Callback)(data).run()
            _log.debug("Invoked callback <{}>.".format(name))

    def _process_evidence(self):
        """
        Main loop that processes the evidence(s) and formats the match(es).

        Parameter(s)
        ------------
        self [namespace] current class instance
        """

        for _, buffer in self.buffers.items():
            for match in buffer.match(self.evidence):
                hashes = {}

                for algorithm in self.algorithms:
                    hashes[algorithm] = self._compute_hash(self.evidence, algorithm=algorithm)

                for action in [self.queue.put, self._invoke_callbacks]:
                    action({
                        "rule": match.rule,
                        "timestamp": datetime.datetime.now().strftime("%Y%m%d%H%M%S"),
                        "target": {
                            "absolute": self.evidence,
                            "basename": os.path.basename(self.evidence)
                        },
                        "meta": match.meta,
                        "namespace": match.namespace,
                        "hashes": hashes,
                        "tags": match.tags,
                        "strings": [{
                            "offset": string[0],
                            "reference": string[1], 
                            "litteral": string[2].decode("utf-8", "backslashreplace")} for string in match.strings]
                    })

    def run(self, evidence, buffers):
        """
        Main entry point for the class.

        Parameter(s)
        ------------
        self [namespace] current class instance
        """

        self.evidence = evidence
        self.buffers = buffers

        self._parse_memory_buffers()
        self._process_evidence()
