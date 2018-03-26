# -*- coding: utf-8 -*-

from framework.api import parser as _parser

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

import os.path

class Pre(_models.Pre):
    _name = os.path.splitext(os.path.basename(__file__))[0]
    _description = "Test preprocessor."
    _author = "sk4la"
    _maintainers = ["sk4la"]
    _version = "0.1"

    def set_args(self):
        self.subparser.add_argument(
            "-i", "--input", required=True, nargs="+", action=_parser.MultipleAbsolutePath, metavar="PATH", 
            help="input test file(s)")

    def run(self, case):
        _log.debug("I'm in.")
        return []
