# -*- coding: utf-8 -*-

from framework.api.renderer import Renderer as _render

from framework.contexts.logger import Logger as _log
from framework.contexts.types import Codes as _codes

class Reader:
    def __init__(self, queue, results, target):
        self.queue = queue
        self.results = results
        self.results["matches"] = 0
        self.target = target

        self.map = {
            "json": self._append_json
        }

    def _append_json(self, data):
        try:
            self.output.write("{}\n".format(_render.to_json(data)))

        except _errors.EncodingError:
            _log.error("Cannot decode data from <{}>.".format(data["target"]["absolute"]))

        except InvalidObject:
            _log.exception("Exception raised while retrieving matching data from <{}>.".format(data["target"]["absolute"]))

    def _open_output_file(self, mode="a", character_encoding="utf-8"):
        try:
            return open(self.target["target"], mode=mode, encoding=character_encoding)

        except (
            OSError,
            Exception):

            _log.fault("Failed to open <{}> for writing.".format(self.target["target"]), trace=True)

    def _read_queue(self):
        while True:
            item = self.queue.get()

            if item == _codes.DONE:
                break

            self.map[self.target["format"]](item)

            self.results["matches"] += 1
            _log.debug("Matching signature from rule <{}> on evidence <{}>.".format(item["rule"], item["target"]["absolute"]))

    def run(self):
        with self._open_output_file() as self.output:
            self._read_queue()

        _log.warning("Total of <{}> matching pattern(s). See <{}> for more details.".format(self.results["matches"], self.target["target"])) if self.results["matches"] else _log.info("No matching pattern(s) found.")
