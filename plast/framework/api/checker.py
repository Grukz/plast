# -*- coding: utf-8 -*-

from framework.contexts import errors as _errors
from framework.contexts.meta import Meta as _meta

import glob
import os.path
import types

try:
    import simplejson as json

except (
    ImportError,
    Exception):

    _log.fault("Import error.", trace=True)

class Checker:
    @staticmethod
    def sanitize_data(data):
        try:
            return (str().join(_ for _ in data.decode("utf-8").strip() if _.isalnum())).strip()

        except AttributeError:
            try:
                return (str().join(_ for _ in data.strip() if _.isalnum())).strip()

            except Exception:
                raise _errors.MalformatedData

        except Exception:
            raise _errors.MalformatedData

    @staticmethod
    def number_rulesets(directory=os.path.join(_meta._root, "rulesets"), globbing_filter="*.yar"):
        return len(glob.glob(os.path.join(directory, "**", globbing_filter), recursive=True))

    @staticmethod
    def check_package(package):
        if not isinstance(package, types.ModuleType):
            raise _errors.InvalidPackage

    @staticmethod
    def check_processor(object, model):
        if not hasattr(object, model.__name__):
            raise _errors.ProcessorNotFound

        if not issubclass(getattr(object, model.__name__), model):
            raise _errors.ProcessorNotInherited
