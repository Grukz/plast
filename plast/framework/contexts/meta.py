# -*- coding: utf-8 -*-

import pathlib

class Meta:
    __root__ = pathlib.Path(__file__).parents[2]
    __description__ = "Modular threat hunting CLI tool."
    __author__ = "sk4la"
    __version__ = "0.1"

    def set_package(target):
        Meta.__package__ = pathlib.PurePath(target).stem
