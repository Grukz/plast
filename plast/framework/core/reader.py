# -*- coding: utf-8 -*-

from framework.api.renderer import Renderer as _render

from framework.contexts.logger import Logger as _log
from framework.contexts.types import Codes as _codes

class Reader:
    """Processes the content from the multiprocessing.Queue instance."""

    def __init__(self, queue, results, target):
        """
        .. py:function:: __init__(self, queue, results, target)

        Initialization method for the class.

        :param self: current class instance
        :type self: class

        :param queue: :code:`multiprocessing.Manager.Queue` instance
        :type queue: class
        
        :param results: :code:`multiprocessing.Value` instance
        :type results: class

        :param target: dictionary containing the absolute path to the output file and the data format to use
        :type target: dict
        """

        self.queue = queue
        self.results = results
        self.target = target

        self.map = {
            "json": self._append_json
        }

    def _append_json(self, data):
        """
        .. py:function:: _append_json(self, data)

        Encodes the match data using the given format and appends the match data to the output file.

        :param self: current class instance
        :type self: class

        :param data: dictionary containing the match data
        :type data: dict
        """

        try:
            self.output.write("{}\n".format(_render.to_json(data)))

        except _errors.EncodingError:
            _log.error("Cannot decode data from <{}>.".format(data["target"]["absolute"]))

        except InvalidObject:
            _log.exception("Exception raised while retrieving matching data from <{}>.".format(data["target"]["absolute"]))

    def _open_output_file(self, mode="a", character_encoding="utf-8"):
        """
        .. py:function:: _open_output_file(self, mode="a", character_encoding="utf-8")

        Opens the output file stream.

        :param self: current class instance
        :type self: class

        :param mode: file opening mode to use
        :type mode: str
        
        :param character_encoding: character encoding to use
        :type character_encoding: str

        :return: descriptor for the newly opened file stream
        :rtype: class
        """

        try:
            return open(self.target["target"], mode=mode, encoding=character_encoding)

        except (
            OSError,
            Exception):

            _log.fault("Failed to open <{}> for writing.".format(self.target["target"]), trace=True)

    def _read_queue(self):
        """
        .. py:function:: _read_queue(self)

        Main loop that processes the match(es) from the :code:`multiprocessing.Queue` instance.

        :param self: current class instance
        :type self: class
        """

        while True:
            item = self.queue.get()

            if item == _codes.DONE:
                break

            self.map[self.target["format"]](item)

            with self.results[0]:
                self.results[1].value += 1

            _log.debug("Matching signature from rule <{}> on evidence <{}>.".format(item["rule"], item["target"]["absolute"]))

    def run(self):
        """
        .. py:function:: run(self)

        Main entry point for the class.

        :param self: current class instance
        :type self: class
        """

        with self._open_output_file() as self.output:
            self._read_queue()

        with self.results[0]:
            _log.warning("Total of <{}> matching pattern(s). See <{}> for more details.".format(self.results[1].value, self.target["target"])) if self.results[1].value else _log.info("No matching pattern(s) found.")
