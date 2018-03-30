# -*- coding: utf-8 -*-

from framework.contexts import models as _models

import os.path

class Post(_models.Post):
    __description__ = "AsciiDoc postprocessor."
    __author__ = "sk4la"
    __version__ = "0.1"

    def __init__(self, case):
        self.case = case
        self.case.resources["report"] = os.path.join(self.case.resources["case"], "report.adoc")
        self.out = open(self.case.resources["report"], "a")

    def __del__(self):
        if hasattr(self, "out"):
            self.out.close()

    def __generate_report(self):
        pass

    def run(self):
        self.__generate_report()
