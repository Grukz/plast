# -*- coding: utf-8 -*-

from framework.contexts import errors as _errors
from framework.contexts.meta import Meta as _meta

import glob
import magic
import os.path
import types

class Checker:
    """Assists data check."""

    @staticmethod
    def sanitize_data(data):
        """
        Strips non white-listed characters from `data`.

        Parameter(s)
        ------------
        data [str] input data to sanitize

        Return value(s)
        ---------------
        [str] sanitized representation of `data`
        """

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
    def number_rulesets(directory=os.path.join(_meta.__root__, "rulesets"), globbing_filter="*.yar"):
        """
        Returns the total number of YARA ruleset(s) in `directory`.

        Parameter(s)
        ------------
        directory [str] absolute path to the rulesets directory (defaults to the project's `rulesets` directory)
        globbing_filter [str] globbing filter to apply for the search (defaults to ".yar")

        Return value(s)
        ---------------
        [int] number of YARA ruleset(s) in `directory`
        """

        return len(glob.glob(os.path.join(directory, "**", globbing_filter), recursive=True))

    @staticmethod
    def check_package(package):
        """
        Checks wether `package` is a valid Python package.

        Parameter(s)
        ------------
        package [namespace] handle to a Python package
        """

        if not isinstance(package, types.ModuleType):
            raise _errors.InvalidPackage

    @staticmethod
    def check_processor(object, model):
        """
        Checks wether `object` is a valid module.

        Parameter(s)
        ------------
        object [namespace] module class handle
        model [namespace] reference module class handle
        """

        if not hasattr(object, model.__name__):
            raise _errors.ProcessorNotFound

        if not issubclass(getattr(object, model.__name__), model):
            raise _errors.ProcessorNotInherited

    @staticmethod
    def check_mime_type(target, types=[]):
        """
        Checks wether the MIME-type of `target` is in `types`.

        Parameter(s)
        ------------
        target [str] absolute path to the file to check
        types [list] list of authorized MIME-types (defaults to [])
        """

        if not magic.from_file(target, mime=True) in types:
            raise _errors.InvalidMIMEType
