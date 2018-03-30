# -*- coding: utf-8 -*-

from framework.api.renderer import Renderer as _render

from framework.contexts.logger import Logger as _log
from framework.contexts.types import Codes as _codes

class Reader:
    def __init__(self, queue, target):
        self.queue = queue
        self.target = target

        self.map = {
            "json": self.__json_append
        }

    def __json_append(self, data):
        try:
            self.output.write("{}\n".format(_render.to_json(data)))

        except _errors.EncodingError:
            _log.error("Cannot decode data from <{}>.".format(data["target"]["absolute"]))

        except InvalidJSONObject:
            _log.exception("Exception raised while retrieving matching data from <{}>.".format(data["target"]["absolute"]))

    def __open_output_file(self, mode="a", character_encoding="utf-8"):
        try:
            return open(self.target["target"], mode=mode, encoding=character_encoding)

        except (
            OSError,
            Exception):

            _log.fault("Failed to open <{}> for writing.".format(self.target["target"]), trace=True)

    def __read_queue(self):
        matches = 0

        while True:
            item = self.queue.get()

            if item == _codes.DONE:
                break

            self.map[self.target["format"]](item)

            matches += 1
            _log.debug("Matching signature from rule <{}> on evidence <{}>.".format(item["rule"], item["target"]["absolute"]))

        return matches

    def run(self):
        with self.__open_output_file() as self.output:
            matches = self.__read_queue()

        _log.warning("Total of <{}> matching pattern(s). See <{}> for more details.".format(matches, self.target["target"])) if matches else _log.info("No matching pattern(s) found.")
