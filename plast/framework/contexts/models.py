# -*- coding: utf-8 -*-

class Pre:
    _name = None
    _authors = []
    _maintainers = []
    _version = None

    def __init__(self, subparser):
        self.subparser = subparser

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

    def __init__(self, case, data):
        self.case = case
        self.data = data

    def run(self):
        pass
