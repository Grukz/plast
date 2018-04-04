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
    def __init__(self, algorithms, callbacks, queue):
        self.algorithms = algorithms
        self.queue = queue
        self.callbacks = callbacks

    def _parse_memory_buffers(self):
        for ruleset, buffer in self.buffers.items():
            buffer.seek(0)
            self.buffers[ruleset] = yara.load(file=buffer)

    def _compute_hash(self, evidence, algorithm="sha256", buffer_size=65536):
        with open(evidence, "rb") as file:
            cipher = getattr(hashlib, algorithm)()

            while True:
                data = file.read(buffer_size)

                if not data:
                    break

                cipher.update(data)
                
        return cipher.hexdigest()

    def _invoke_callbacks(self, data):
        for name in self.callbacks:
            _loader.load_processor(name, _models.Callback)(data).run()
            _log.debug("Invoked callback <{}>.".format(name))

    def _process_evidence(self):
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
        self.evidence = evidence
        self.buffers = buffers

        self._parse_memory_buffers()
        self._process_evidence()
