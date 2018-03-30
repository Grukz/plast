# -*- coding: utf-8 -*-

class Pre:
    __description__ = None
    __author__ = None
    __version__ = None

    def __init__(self, parser):
        pass

    def init_case(self, case):
        self.case = case

    def run(self, case):
        return []

class Post:
    __description__ = None
    __author__ = None
    __version__ = None

    def __init__(self, case):
        self.case = case

    def run(self):
        pass

class Callback:
    __description__ = None
    __author__ = None
    __version__ = None

    def __init__(self, case):
        self.case = case

    def run(self):
        pass
