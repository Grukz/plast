# -*- coding: utf-8 -*-

from framework.api.external import filesystem as _fs
from framework.api.internal import parser as _parser

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

import os.path

class Pre(_models.Pre):
    __author__ = "sk4la"
    __description__ = "Simple preprocessing module that feeds file(s) to the engine."
    __license__ = "MIT <https://raw.githubusercontent.com/sk4la/plast/master/LICENSE>"
    __maintainer__ = ["sk4la"]
    __system__ = ["Darwin", "Linux", "Windows"]
    __version__ = "0.1"

    def __init__(self, parser):
        """
        .. py:function:: __init__(self, parser)

        Initialization method for the class.

        :param self: current class instance
        :type self: class

        :param parser: :code:`argparse.Parser.subparser` instance
        :type parser: list
        """

        parser.add_argument(
            "-i", "--input", nargs="+", action=_parser.MultipleAbsolutePath, required=True, metavar="PATH", 
            help="input file(s) or directory(ies)")

        parser.add_argument(
            "-r", "--recursive", action="store_true", 
            help="walk through directory(ies) recursively")

        parser.add_argument(
            "--filters", nargs="+", default=["*"], metavar="FILTER", 
            help="custom shell-like globbing filter(s)")

    def _track_files(self):
        """
        .. py:function:: _track_files(self)

        Iterates through file(s) and directory(ies) to track valid evidence(s).

        :param self: current class instance
        :type self: class
        """

        for item in self.case.arguments.input:
            if os.path.isfile(item):
                self.case.track_file(file)

            elif os.path.isdir(item):
                for file in _fs.enumerate_matching_files(item, self.case.arguments.filters, recursive=self.case.arguments.recursive):
                    if os.path.isfile(file):
                        self.case.track_file(file)

            else:
                _log.warning("Unknown inode type for object <{}>.".format(item))

    def run(self):
        """
        .. py:function:: run(self)

        Main entry point for the module.

        :param self: current class instance
        :type self: class
        """

        if self.case.arguments.input:
            self._track_files()
