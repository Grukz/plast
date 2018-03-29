# -*- coding: utf-8 -*-

from framework.contexts.logger import Logger as _log

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
    def __init__(self, queue, algorithms):
        self.queue = queue
        self.algorithms = algorithms

    def __parse_memory_buffers(self):
        for ruleset, buffer in self.buffers.items():
            buffer.seek(0)
            self.buffers[ruleset] = yara.load(file=buffer)

    def __compute_hash(self, evidence, algorithm="sha256", buffer_size=65536):
        with open(evidence, "rb") as file:
            cipher = getattr(hashlib, algorithm)()

            while True:
                data = file.read(buffer_size)

                if not data:
                    break

                cipher.update(data)
                
        return cipher.hexdigest()

    def __process_evidence(self):
        for _, buffer in self.buffers.items():
            for match in buffer.match(self.evidence):
                hashes = {}

                for algorithm in self.algorithms:
                    hashes[algorithm] = self.__compute_hash(self.evidence, algorithm=algorithm)

                self.queue.put({
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

        self.__parse_memory_buffers()
        self.__process_evidence()
