# -*- coding: utf-8 -*-

from framework.api import parser as _parser
from framework.api.renderer import Renderer as _renderer

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

import glob
import os.path

class Pre(_models.Pre):
    __author__ = "sk4la"
    __maintainers__ = ["sk4la"]
    __description__ = "Simple filesystem-based preprocessor."
    __version__ = "0.1"

    def __init__(self, parser):
        parser.add_argument(
            "--filter", default="*", metavar="FILTER", 
            help="custom globbing filter")

        parser.add_argument(
            "-i", "--input", required=True, nargs="+", action=_parser.MultipleAbsolutePath, metavar="PATH", 
            help="input test file(s) or directory(ies)")

    def __enumerate_files(self, directory):
        for file in glob.iglob(os.path.join(directory, "**", self.case.arguments.filter), recursive=True):
            yield file

    def __track_evidences(self):
        evidences = []

        for item in self.case.arguments.input:
            if os.path.isfile(item):
                _log.debug("Tracking evidence <{}>.".format(item))
                evidences.append(file)

            elif os.path.isdir(item):
                for file in self.__enumerate_files(item):
                    if os.path.isfile(file):
                        _log.debug("Tracking evidence <{}>.".format(file))
                        evidences.append(file)

            else:
                _log.warning("Unknown inode type for object <{}>.".format(item))

        return evidences

    def run(self):
        return self.__track_evidences()
