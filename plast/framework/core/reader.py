# # -*- coding: utf-8 -*-

# from framework.contexts.logger import Logger as _log
# from framework.contexts.types import Codes as _codes

# class Reader:
#     def __init__(self, queue, output_file, output_format):
#         self.queue = queue
#         self.output_file = output_file
#         self.output_format = output_format

#         self.format_map = {
#             "JSON": self.__json_append
#         }

#     def __json_append(self, data):
#         try:
#             self.out.write("{}\n".format(json.dumps(data)))

#         except UnicodeDecodeError:
#             _log.error("Current codec cannot decode data from <{}> to append to the output file.".format(data["target"]["absolute"]))

#         except Exception:
#             _log.exception("Exception raised while appending result data from <{}> to the output file.".format(data["target"]["absolute"]))

#     def __open_output_file(self, mode="a", character_encoding="utf-8"):
#         try:
#             return open(self.output_file, mode=mode, encoding=character_encoding)

#         except (
#             OSError,
#             Exception):

#             _log.fault("Failed to open the output file <{}> for writing.".format(self.output_file), trace=True)

#     def __read_queue(self):
#         matches = 0

#         while True:
#             item = self.queue.get()

#             if item == _types.DONE:
#                 break

#             self.format_map[self.output_format](item)

#             matches += 1
#             _log.debug("Matching signature from rule <{}> on host <{}>.".format(item["rule"], item["host"]))

#         return matches

#     def run(self):
#         with self.__open_output_file() as self.out:
#             matches = self.__read_queue()
#             _log.warning("Total of <{}> matching pattern(s).".format(matches)) if matches else _log.info("No matching pattern(s) found.")
