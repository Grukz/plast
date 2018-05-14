# -*- coding: utf-8 -*-

from framework.api.internal.renderer import Renderer as _renderer

import pathlib

__all__ = [
    "Configuration",
    "Meta"
]

class Configuration:
    """Container for the local configuration."""

    def _load_configuration(configuration):
        with open(configuration) as conf:
            for key, value in _renderer.from_json(conf.read()).items():
                setattr(Configuration, key, value)

class Meta:
    """Contains the metadata for the program."""

    __author__ = "sk4la"
    __description__ = "Modular threat hunting CLI tool."
    __package__ = "plast"
    __root__ = pathlib.Path(__file__).parents[2]
    __config__ = __root__ / "configuration.json"
    __version__ = "0.1"

    def set_package(target):
        """
        .. py:function:: set_package(target)

        Sets the package name from the target's absolute path.

        :param target: absolute path to the base module of the program
        :type target: str
        """

        Meta.__package__ = pathlib.PurePath(target).stem
