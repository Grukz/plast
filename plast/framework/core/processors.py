# -*- coding: utf-8 -*-

from framework.api.loader import Loader as _loader

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

import datetime
import hashlib
import os.path

class File:
    """Core multiprocessed class that processes the file-based evidence(s) asynchronously."""

    def __init__(self, algorithms, callbacks, queue):
        """
        .. py:function:: __init__(self, algorithms, callbacks, queue)

        Initialization method for the class.

        :param self: current class instance
        :type self: class

        :param algorithms: list containing the name of the hash algorithm(s) to use
        :type algorithms: list

        :param callbacks: list containing the name of the :code:`models.Callback` modules to invoke
        :type callbacks: list
        
        :param queue: :code:`multiprocessing.Manager.Queue` instance
        :type queue: class
        """

        self.algorithms = algorithms
        self.queue = queue
        self.callbacks = callbacks

    def _compute_hash(self, evidence, algorithm="sha256", buffer_size=65536):
        """
        .. py:function:: _compute_hash(self, evidence, algorithm="sha256", buffer_size=65536)

        Computes the hash from the evidence's data.

        :param self: current class instance
        :type self: class

        :param evidence: absolute path to the evidence to compute the hash from
        :type evidence: str

        :param algorithm: lowercase name of the hash algorithm to compute
        :type algorithm: str

        :param buffer_size: size of the buffer
        :type buffer_size: int

        :return: hexadecimal digest of the given file
        :rtype: str
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
        .. py:function:: _invoke_callbacks(self, data)

        Invokes the selected :code:`models.Callback` module(s) with the matching data.

        :param self: current class instance
        :type self: class

        :param data: dictionary containing the match data
        :type data: dict
        """

        for name in self.callbacks:
            _loader.load_processor(name, _models.Callback)(data).run()
            _log.debug("Invoked callback <{}>.".format(name))

    def _process_evidence(self):
        """
        .. py:function:: _process_evidence(self)

        Main loop that processes the evidence(s) and formats the match(es).

        :param self: current class instance
        :type self: class
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
                            "type": "file",
                            "identifier": self.evidence
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
        .. py:function:: run(self, evidence, buffers)

        Main entry point for the class.

        :param self: current class instance
        :type self: class

        :param evidence: absolute path to the evidence file to process
        :type evidence: str

        :param buffers: dictionary containing precompiled YARA rule(s)
        :type buffers: dict
        """

        self.evidence = evidence
        self.buffers = buffers

        _loader._load_memory_buffers(self.buffers)
        self._process_evidence()

class Process:
    """Core multiprocessed class that processes the process-based evidence(s) asynchronously."""

    def __init__(self, callbacks, queue):
        """
        .. py:function:: __init__(self, callbacks, queue)

        Initialization method for the class.

        :param self: current class instance
        :type self: class

        :param callbacks: list containing the name of the :code:`models.Callback` modules to invoke
        :type callbacks: list
        
        :param queue: :code:`multiprocessing.Manager.Queue` instance
        :type queue: class
        """

        self.queue = queue
        self.callbacks = callbacks

    def _invoke_callbacks(self, data):
        """
        .. py:function:: _invoke_callbacks(self, data)

        Invokes the selected :code:`models.Callback` module(s) with the matching data.

        :param self: current class instance
        :type self: class

        :param data: dictionary containing the match data
        :type data: dict
        """

        for name in self.callbacks:
            _loader.load_processor(name, _models.Callback)(data).run()
            _log.debug("Invoked callback <{}>.".format(name))

    def _process_evidence(self):
        """
        .. py:function:: _process_evidence(self)

        Main loop that processes the evidence(s) and formats the match(es).

        :param self: current class instance
        :type self: class
        """

        for _, buffer in self.buffers.items():
            for match in buffer.match(pid=self.evidence):
                for action in [self.queue.put, self._invoke_callbacks]:
                    action({
                        "rule": match.rule,
                        "timestamp": datetime.datetime.now().strftime("%Y%m%d%H%M%S"),
                        "target": {
                            "type": "process",
                            "identifier": self.evidence
                        },
                        "meta": match.meta,
                        "namespace": match.namespace,
                        "tags": match.tags,
                        "strings": [{
                            "offset": string[0],
                            "reference": string[1], 
                            "litteral": string[2].decode("utf-8", "backslashreplace")} for string in match.strings]
                    })

    def run(self, evidence, buffers):
        """
        .. py:function:: run(self, evidence, buffers)

        Main entry point for the class.

        :param self: current class instance
        :type self: class

        :param evidence: dictionary containing key/value association of a process
        :type evidence: dict

        :param buffers: dictionary containing precompiled YARA rule(s)
        :type buffers: dict
        """

        self.evidence = evidence
        self.buffers = buffers

        _loader._load_memory_buffers(self.buffers)
        self._process_evidence()
