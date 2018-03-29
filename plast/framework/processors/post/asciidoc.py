# -*- coding: utf-8 -*-

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

import os.path

class Post(_models.Post):
    _name = os.path.splitext(os.path.basename(__file__))[0]
    _description = "AsciiDoc postprocessor."
    _authors = ["sk4la"]
    _maintainers = ["sk4la"]
    _version = "0.1"

    _tags = {
        "heading": "=",
        "code": "----"
    }

    def __init__(self, case):
        self.case = case
        self.case.resources["report"] = os.path.join(self.case.resources["case"], "report.adoc")
        self.out = open(self.case.resources["report"], "a")

    def __heading(self, content, level=1):
        if level not in range(1, 5):
            level = 1

        self.out.write("{} {}\n\n".format(self._tags["heading"] * level, content))

    def __code(self, content):
        self.out.write("{0}\n{1}\n{0}\n\n".format(self._tags["code"], content))

    def __generate_report(self):
        self.__heading("Main title")
        self.__code("# python -m venv .env")

    def run(self):
        self.__generate_report()
