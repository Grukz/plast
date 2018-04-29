# -*- coding: utf-8 -*-

from framework.api.loader import Loader as _loader

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log
from framework.contexts.meta import Configuration as _conf
from framework.contexts.meta import Meta as _meta

import hashlib
import os.path

try:
    import pendulum
    import yara

except (
    ImportError,
    Exception):

    _log.fault("Import error.", trace=True)

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
            _loader.load_processor(name, _models.Callback)().run(data)
            _log.debug("Invoked callback <{}>.".format(name))

    def _process_evidence(self):
        """
        .. py:function:: _process_evidence(self)

        Main loop that processes the evidence(s) and formats the match(es).

        :param self: current class instance
        :type self: class
        """

        for _, buffer in self.buffers.items():
            try:
                for match in buffer.match(self.evidence, timeout=_conf.YARA_MATCH_TIMEOUT):
                    hashes = {}

                    for algorithm in self.algorithms:
                        hashes[algorithm] = self._compute_hash(self.evidence, algorithm=algorithm)

                    for action in [self.queue.put, self._invoke_callbacks]:
                        action({
                            "origin": _meta.__package__,
                            "target": {
                                "type": "file",
                                "identifier": self.evidence
                            },
                            "match": {
                                "timestamp": pendulum.now().to_datetime_string(),
                                "rule": match.rule,
                                "meta": match.meta,
                                "namespace": match.namespace,
                                "tags": match.tags,
                                "hashes": hashes,
                                "strings": [{
                                    "offset": string[0],
                                    "reference": string[1], 
                                    "litteral": string[2].decode("utf-8", "backslashreplace")} for string in match.strings]
                            }
                        })

            except yara.TimeoutError:
                _log.warning("Timeout exceeded for file-based evidence <{}>.".format(self.evidence))
                continue

            except yara.Error:
                _log.exception("YARA exception raised during processing of file-based evidence <{}>.".format(self.evidence))
                continue

            except Exception:
                _log.exception("YARA exception raised during processing of file-based evidence <{}>.".format(self.evidence))
                continue

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
            _loader.load_processor(name, _models.Callback)().run(data)
            _log.debug("Invoked callback <{}>.".format(name))

    def _process_evidence(self):
        """
        .. py:function:: _process_evidence(self)

        Main loop that processes the evidence(s) and formats the match(es).

        :param self: current class instance
        :type self: class
        """

        for _, buffer in self.buffers.items():
            try:
                for match in buffer.match(pid=self.evidence, timeout=_conf.YARA_MATCH_TIMEOUT):
                    for action in [self.queue.put, self._invoke_callbacks]:
                        action({
                            "origin": _meta.__package__,
                            "target": {
                                "type": "process",
                                "identifier": self.evidence
                            },
                            "match": {
                                "timestamp": pendulum.now().to_datetime_string(),
                                "rule": match.rule,
                                "meta": match.meta,
                                "namespace": match.namespace,
                                "tags": match.tags,
                                "hashes": [],
                                "strings": [{
                                    "offset": string[0],
                                    "reference": string[1], 
                                    "litteral": string[2].decode("utf-8", "backslashreplace")} for string in match.strings]
                            }
                        })

            except yara.TimeoutError:
                _log.warning("Timeout exceeded for live process matching PID <{}>.".format(self.evidence))
                continue

            except yara.Error:
                _log.exception("YARA exception raised during processing of live process matching PID <{}>.".format(self.evidence))
                continue

            except Exception:
                _log.exception("YARA exception raised during processing of live process matching PID <{}>.".format(self.evidence))
                continue

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
