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

    def run(self):
        _log.debug("Let's pretend this is AsciiDoc.")
