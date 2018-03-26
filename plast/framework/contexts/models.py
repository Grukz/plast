# -*- coding: utf-8 -*-

class Pre:
    _name = None
    _author = None
    _maintainers = []
    _version = None

    def __init__(self, subparser):
        self.subparser = subparser

    def set_args(self):
        pass

    def run(self):
        return []

class Post:
    _name = None
    _author = None
    _maintainers = []
    _version = None

    def __init__(self, subparser):
        self.subparser = subparser

    def run(self):
        return []
