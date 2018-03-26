# -*- coding: utf-8 -*-

from framework.api.checker import Checker as _checker

from framework.contexts import errors as _errors
from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log
from framework.contexts.meta import Meta as _meta

import glob
import importlib
import os.path
import pkgutil

class Loader:
    @staticmethod
    def load_processor(name, model):
        processor = importlib.import_module("framework.processors.{}.{}".format(model.__name__.lower(), name))

        try:
            _checker.check_processor(processor, model)

        except _errors.ProcessorNotFound:
            _log.fault("No subclass found in module <{}>.".format(name), trace=True)

        except _errors.ProcessorNotInherited:
            _log.fault("Processor <{}.{}> not inheriting from the base class.".format(name, model.__name__), trace=True)

        return getattr(processor, model.__name__)

    @staticmethod
    def iterate_rulesets(directory=os.path.join(_meta._root, "rulesets"), globbing_filter="*.yar"):
        for file in glob.iglob(os.path.join(directory, "**", globbing_filter), recursive=True):
            yield os.path.splitext(os.path.basename(file))[0], file

    @staticmethod
    def iterate_processors(package, model):
        for _, name, __ in pkgutil.iter_modules(package.__path__):
            yield name, Loader.load_processor(name, model)

    @staticmethod
    def render_processors(package, model):
        try:
            _checker.check_package(package)

        except _errors.InvalidPackage:
            _log.fault("Invalid package <{}>.".format(package), trace=True)

        return [os.path.splitext(name)[0] for name, _ in Loader.iterate_processors(package, model)]
