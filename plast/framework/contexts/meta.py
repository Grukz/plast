# -*- coding: utf-8 -*-

import pathlib

class Meta:
    """Contains the metadata for the program."""

    __root__ = pathlib.Path(__file__).parents[2]
    __description__ = "Modular threat hunting CLI tool."
    __author__ = "sk4la"
    __version__ = "0.1"

    def set_package(target):
        """
        Sets the package name from the target's absolute path.

        Parameter(s)
        ------------
        target [str] absolute path to the base module of the program.
        """

        Meta.__package__ = pathlib.PurePath(target).stem
