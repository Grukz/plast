# -*- coding: utf-8 -*-

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

import sys

try:
    from pygments import highlight
    from pygments.formatters import TerminalFormatter
    from pygments.lexers import JsonLexer

    import simplejson as json

except (
    ImportError,
    Exception):

    _log.fault("Import error.", trace=True)

class Callback(_models.Callback):
    __author__ = "sk4la"
    __description__ = "Simple callback tailing and beautifying match(es)."
    __license__ = "MIT <https://github.com/sk4la/plast/blob/master/LICENSE.adoc>"
    __maintainer__ = ["sk4la"]
    __system__ = ["Darwin", "Linux", "Windows"]
    __version__ = "0.1"

    def run(self, data):
        sys.stdout.write(highlight(json.dumps(data, indent=4, sort_keys=True), JsonLexer(), TerminalFormatter()))
