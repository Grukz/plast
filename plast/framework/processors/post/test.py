# -*- coding: utf-8 -*-

from framework.api import parser as _parser

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

import os.path

class Post(_models.Post):
    _name = os.path.splitext(os.path.basename(__file__))[0]
    _description = "Test postprocessor."
    _author = "sk4la"
    _maintainers = ["sk4la"]
    _version = "0.1"

    def run(self, case):
        _log.debug("I'm in.")
