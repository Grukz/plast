# -*- coding: utf-8 -*-

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

class Callback(_models.Callback):
    __author__ = "sk4la"
    __description__ = "Test callback."
    __license__ = "MIT <https://raw.githubusercontent.com/sk4la/plast/master/LICENSE>"
    __maintainer__ = ["sk4la"]
    __system__ = ["Darwin", "Linux", "Windows"]
    __version__ = "0.1"

    def run(self, data):
        _log.debug("This is a test callback invoked to process data <{}>.".format(data))
