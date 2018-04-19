# -*- coding: utf-8 -*-

from framework.api import parser as _parser

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

import glob
import os.path

class Pre(_models.Pre):
    __description__ = "Simple filesystem-based preprocessor."
    __author__ = "sk4la"
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
            "--filter", default="*", metavar="FILTER", 
            help="custom globbing filter")

        parser.add_argument(
            "-i", "--input", required=True, nargs="+", action=_parser.MultipleAbsolutePath, metavar="PATH", 
            help="input test file(s) or directory(ies)")

    def _enumerate_files(self, directory):
        """
        .. py:function:: _enumerate_files(self, directory)

        Recursively iterates through the file(s) in a directory.

        :param self: current class instance
        :type self: class

        :param directory: path to the directory to walk through
        :type directory: str

        :return: path to the matching file(s)
        :rtype: str
        """

        for file in glob.iglob(os.path.join(directory, "**", self.case.arguments.filter), recursive=True):
            yield file

    def _track_evidences(self):
        """
        .. py:function:: _track_evidences(self)

        Iterates through file(s) and directory(ies) to track valid evidence(s).

        :param self: current class instance
        :type self: class
        """

        evidences = []

        for item in self.case.arguments.input:
            if os.path.isfile(item):
                self.case.track_file(file)

            elif os.path.isdir(item):
                for file in self._enumerate_files(item):
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

        self._track_evidences()
