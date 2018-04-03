# -*- coding: utf-8 -*-

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

import os.path

class Post(_models.Post):
    __description__ = "AsciiDoc postprocessor."
    __author__ = "sk4la"
    __version__ = "0.1"

    def __init__(self, case):
        self.case = case
        self.case.resources["report"] = os.path.join(self.case.resources["case"], "report.adoc")

        try:
            self.out = open(self.case.resources["report"], "a")

        except Exception:
            _log.error("Failed to open the output stream to <{}>".format(self.case.resources["report"]))

    def __del__(self):
        if hasattr(self, "out"):
            self.out.close()

    def __generate_report(self):
        _log.debug("AsciiDoc report anchored to <{}>.".format(self.case.resources["report"]))

    def run(self):
        if not hasattr(self, "out"):
            self.__generate_report()
