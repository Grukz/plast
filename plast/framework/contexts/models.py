# -*- coding: utf-8 -*-

class Pre:
    __version__ = None
    __description__ = None
    __author__ = None
    __maintainers__ = []

    def __init__(self, parser):
        pass

    def init_case(self, case):
        self.case = case

    def run(self, case):
        return []

class Post:
    __version__ = None
    __description__ = None
    __author__ = None
    __maintainers__ = []

    def __init__(self, case):
        self.case = case

    def run(self):
        pass

class Callback:
    __version__ = None
    __description__ = None
    __author__ = None
    __maintainers__ = []

    def __init__(self, case):
        self.case = case

    def run(self):
        pass
