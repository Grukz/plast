# -*- coding: utf-8 -*-

from framework.api.external import filesystem as _fs
from framework.api.internal.checker import Checker as _checker

from framework.contexts import errors as _errors
from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log
from framework.contexts.configuration import Configuration as _conf
from framework.contexts.meta import Meta as _meta

import importlib
import os.path
import pkgutil
import platform

try:
    import yara

except (
    ImportError,
    Exception):

    _log.fault("Import error.", trace=True)

__all__ = [
    "Loader"
]

class Loader:
    """Assists modules load."""

    @staticmethod
    def load_module(name, model, silent=False):
        """
        .. py:function:: load_module(name, model)

        Dynamically loads a registered module.

        :param name: name of the module to load
        :type name: str

        :param model: reference class handle
        :type model: class

        :param silent: suppress the warning message
        :type silent: bool

        :return: module class handle
        :rtype: class
        """

        module = importlib.import_module("framework.modules.{}.{}".format(model.__name__.lower(), name))

        try:
            _checker.check_module(module, model)

        except _errors.NotFoundError:
            _log.fault("No subclass found in module <{}.{}>. Quitting.".format(model.__name__.lower(), name), trace=True)

        except _errors.ModuleInheritanceError:
            _log.fault("Module <{}.{}> not inheriting from the base class. Quitting.".format(model.__name__.lower(), name), trace=True)

        except _errors.SystemNotSupportedError:
            if model.__name__ == _models.Pre.__name__:
                _log.fault("Module <{}.{}> does not support the current system <{}>. Quitting.".format(model.__name__.lower(), name, platform.system()))  

            elif not silent:
                _log.warning("Module <{}.{}> incompatible with the current system <{}>. Ignoring.".format(model.__name__.lower(), name, platform.system()))
                return None

        return getattr(module, model.__name__)

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

        for file in _fs.enumerate_matching_files(directory, globbing_filters, recursive=True):
            yield os.path.splitext(os.path.basename(file))[0], file

    @staticmethod
    def iterate_modules(package, model, silent=False):
        """
        .. py:function:: iterate_modules(package, model)

        Iterates through the available YARA ruleset(s).

        :param package: package handle to import module(s) from
        :type package: class

        :param model: reference module class handle
        :type model: class

        :param silent: suppress the warning message
        :type silent: bool

        :return: name of the current module and its handle
        :rtype: tuple
        """

        for _, name, __ in pkgutil.iter_modules(package.__path__):
            yield name, Loader.load_module(name, model, silent=silent)

    @staticmethod
    def render_modules(package, model):
        """
        .. py:function:: render_modules(package, model)

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

        except _errors.InvalidPackageError:
            _log.fault("Invalid package <{}>.".format(package), trace=True)

        return [os.path.splitext(name)[0] for name, _ in Loader.iterate_modules(package, model, silent=True)]

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
