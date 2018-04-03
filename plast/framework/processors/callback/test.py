# -*- coding: utf-8 -*-

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

class Callback(_models.Callback):
    __description__ = "Test callback."
    __author__ = "sk4la"
    __version__ = "0.1"

    def run(self):
        _log.debug("This is a test callback.")
