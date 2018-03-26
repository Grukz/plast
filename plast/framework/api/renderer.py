# -*- coding: utf-8 -*-

from framework.contexts import errors as _errors

try:
    import simplejson as json

except (
    ImportError,
    Exception):

    _log.fault("Import error.", trace=True)

class Renderer:
    @staticmethod
    def from_json(data):
        try:
            return json.loads(data)

        except (
            OverflowError,
            TypeError,
            ValueError,
            Exception):

            raise _errors.InvalidJSONObject

    @staticmethod
    def to_json(data):
        try:
            return json.dumps(data)

        except (
            OverflowError,
            TypeError,
            ValueError,
            Exception):

            raise _errors.InvalidJSONObject
