# -*- coding: utf-8 -*-

from framework.api import magic as _magic
from framework.api.checker import Checker as _checker

from framework.contexts import errors as _errors
from framework.contexts.logger import Logger as _log
from framework.contexts.meta import Configuration as _conf
from framework.contexts.meta import Meta as _meta

import importlib
import os.path
import pkgutil

try:
    import yara

except (
    ImportError,
    Exception):

    _log.fault("Import error.", trace=True)

class Loader:
    """Assists modules load."""

    @staticmethod
    def load_processor(name, model):
        """
        .. py:function:: load_processor(name, model)

        Dynamically loads a registered module.

        :param name: name of the module to load
        :type name: str

        :param model: reference class handle
        :type model: class

        :return: module class handle
        :rtype: class

        :raises ProcessorNotFound: if no subclass of one of the reference models can be found in :code:`name`
        :raises ProcessorNotInherited: if the class found in :code:`name` does not inherit from the reference class :code:`model`
        """

        processor = importlib.import_module("framework.processors.{}.{}".format(model.__name__.lower(), name))

        try:
            _checker.check_processor(processor, model)

        except _errors.ProcessorNotFound:
            _log.fault("No subclass found in module <{}>.".format(name), trace=True)

        except _errors.ProcessorNotInherited:
            _log.fault("Processor <{}.{}> not inheriting from the base class.".format(name, model.__name__), trace=True)

        return getattr(processor, model.__name__)

    @staticmethod
    def iterate_rulesets(directory=os.path.join(_meta.__root__, "rulesets"), globbing_filters=_conf.YARA_EXTENSION_FILTERS):
        """
        .. py:function:: iterate_rulesets(directory=os.path.join(_meta.__root__, "rulesets"), globbing_filters=_conf.YARA_EXTENSION_FILTERS)

        Iterates through the available YARA ruleset(s).

        :param directory: absolute path to the rulesets directory
        :type directory: str

        :param globbing_filters: list of globbing filter to apply for the search
        :type globbing_filters: list

        :return: basename and absolute path to the current ruleset
        :rtype: tuple
        """

        for file in _magic.enumerate_matching_files(directory, globbing_filters, recursive=True):
            yield os.path.splitext(os.path.basename(file))[0], file

    @staticmethod
    def iterate_processors(package, model):
        """
        .. py:function:: iterate_processors(package, model)

        Iterates through the available YARA ruleset(s).

        :param package: package handle to import module(s) from
        :type package: class

        :param model: reference module class handle
        :type model: class

        :return: name of the current module and its handle
        :rtype: tuple
        """

        for _, name, __ in pkgutil.iter_modules(package.__path__):
            yield name, Loader.load_processor(name, model)

    @staticmethod
    def render_processors(package, model):
        """
        .. py:function:: render_processors(package, model)

        Renders available module(s) name(s) as a list.

        :param package: package handle to import module(s) from
        :type package: class

        :param model: reference module class handle
        :type model: class

        :return: available module(s) in :code:`package`
        :rtype: list
        """

        try:
            _checker.check_package(package)

        except _errors.InvalidPackage:
            _log.fault("Invalid package <{}>.".format(package), trace=True)

        return [os.path.splitext(name)[0] for name, _ in Loader.iterate_processors(package, model)]

    @staticmethod
    def _load_memory_buffers(buffers):
        """
        .. py:function:: _load_memory_buffers(self)

        Parses memory buffers to retrieve the content of the YARA rules to apply.

        :param buffers: dictionary containing key/value associations of rule(s) to load
        :type buffers: dict
        """

        for ruleset, buffer in buffers.items():
            buffer.seek(0)
            buffers[ruleset] = yara.load(file=buffer)
