# -*- coding: utf-8 -*-

class Hole:
    def __init__(self, target, action=None):
        self.target = target
        self.action = action

    def __enter__(self):
        pass

    def __exit__(self, exception, *args):
        if exception and issubclass(exception, self.target):
            if self.action:
                self.action()

            return True
        return False
