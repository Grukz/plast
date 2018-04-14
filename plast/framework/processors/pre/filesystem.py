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
        Initialization method that sets the different command-line argument(s).

        Parameter(s)
        ------------
        self [namespace] current class instance
        parser [namespace] argparse.Parser.subparser instance
        """

        parser.add_argument(
            "--filter", default="*", metavar="FILTER", 
            help="custom globbing filter")

        parser.add_argument(
            "-i", "--input", required=True, nargs="+", action=_parser.MultipleAbsolutePath, metavar="PATH", 
            help="input test file(s) or directory(ies)")

    def _enumerate_files(self, directory):
        """
        Iterates through the files in a directory.

        Parameter(s)
        ------------
        self [namespace] current class instance
        directory [str] path to the directory to walk through

        Return value(s)
        ---------------
        [str] path to the matching file(s)
        """

        for file in glob.iglob(os.path.join(directory, "**", self.case.arguments.filter), recursive=True):
            yield file

    def _track_evidences(self):
        """
        Iterates through file(s) and directory(ies) to track valid evidence(s).

        Parameter(s)
        ------------
        self [namespace] current class instance

        Return value(s)
        ---------------
        [list] list containing the absolute path(s) of the evidence(s) to process
        """

        evidences = []

        for item in self.case.arguments.input:
            if os.path.isfile(item):
                _log.debug("Tracking evidence <{}>.".format(item))
                evidences.append(file)

            elif os.path.isdir(item):
                for file in self._enumerate_files(item):
                    if os.path.isfile(file):
                        _log.debug("Tracking evidence <{}>.".format(file))
                        evidences.append(file)

            else:
                _log.warning("Unknown inode type for object <{}>.".format(item))

        return evidences

    def run(self):
        """
        Main entry point for the module.

        Parameter(s)
        ------------
        self [namespace] current class instance

        Return value(s)
        ---------------
        [list] list containing the absolute path(s) of the evidence(s) to process
        """

        return self._track_evidences()
