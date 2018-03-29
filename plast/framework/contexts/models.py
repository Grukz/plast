# -*- coding: utf-8 -*-

class Pre:
    _name = None
    _authors = []
    _maintainers = []
    _version = None

    def __init__(self, parser):
        self.parser = parser

    def set_args(self):
        pass

    def init_case(self, case):
        self.case = case

    def run(self, case):
        return []

class Post:
    _name = None
    _authors = []
    _maintainers = []
    _version = None

    def __init__(self, case):
        self.case = case

    def run(self):
        pass

class Callback:
    _name = None
    _authors = []
    _maintainers = []
    _version = None

    def __init__(self, case):
        self.case = case

    def run(self):
        pass
