# -*- coding: utf-8 -*-

from framework.contexts.logger import Logger as _log

class Pre:
    """Base preprocessor class."""

    __slots__ = [
        "__author__", 
        "__description__", 
        "__license__",
        "__maintainer__",
        "__system__",
        "__version__"
    ]

    def __init__(self, parser):
        pass

    def run(self):
        _log.warning("Unimplemented <{}> module.".format(self.__class__.__name__))

class Post:
    """Base postprocessor class."""

    __slots__ = [
        "__author__", 
        "__description__", 
        "__license__",
        "__maintainer__",
        "__system__",
        "__version__"
    ]

    def run(self, case):
        _log.warning("Unimplemented <{}> module.".format(self.__class__.__name__))

class Callback:
    """Base callback class."""

    __slots__ = [
        "__author__", 
        "__description__", 
        "__license__",
        "__maintainer__",
        "__system__",
        "__version__"
    ]

    def run(self, data):
        _log.warning("Unimplemented <{}> module.".format(self.__class__.__name__))
